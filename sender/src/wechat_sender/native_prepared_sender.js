/* SPDX-License-Identifier: GPL-3.0-only
 * Experimental, exact-build native text sender. PROFILE is host supplied after
 * verifying the on-disk arm64 code hash and every expected instruction prefix.
 * Loading/status do not construct a Task, change a hook, or submit anything.
 * prepare() performs a local native lifecycle smoke check and installs an
 * exact-owned-task completion dispatcher. arm() is a one-use host authorization.
 * Native account framing, transport and response decoding remain unchanged.
 */
'use strict';

const MAX_OPERATIONS = 32;
const MAX_WIRE = 8192;
const CGI = '/cgi-bin/micromsg-bin/newsendmsg';
const SOURCE_XML = '<msgsource><alnode><fr>1</fr></alnode></msgsource>';
const sender = {
  phase: 'unprepared', diagnostic_code: null, prepared: false, preparing: false,
  permit: null, native: null, module: null, addresses: null, account_identity: null,
  owned_ranges: [],
  operations: new Map(), byTask: new Map(), active: null,
  callback_depth: 0, start_in_progress: false, dispatch: null, pinned: false,
  smoke: null, completed: 0, native_failures: 0
};

function fail(code) { throw new Error(code); }
function enabled() {
  return PROFILE.sending_permitted === true && PROFILE.send_framing_verified === true;
}
function safeError(error, fallback) {
  return error && /^[a-z][a-z0-9_]{0,80}$/.test(error.message) ? error.message : fallback;
}
function readable(address, size) {
  if (!address || address.isNull() || !Number.isSafeInteger(size) || size < 0) return false;
  // Frida cloaks its own Memory.alloc ranges from Process.findRangeByAddress.
  // Retained allocations have explicit bounds; native buffers still require
  // their own validated length/capacity and readable backing pages below.
  if (sender.owned_ranges.some(r => address.compare(r.base) >= 0
      && address.add(size).compare(r.base.add(r.size)) <= 0)) return true;
  const range = Process.findRangeByAddress(address);
  if (range !== null && range.protection.indexOf('r') >= 0
      && address.add(size).compare(range.base.add(range.size)) <= 0) return true;
  if (typeof Memory.queryProtection !== 'function') return false;
  try {
    // queryProtection examines actual mapped pages, including cloaked pages.
    // Check every touched page without copying or logging its contents.
    if (Memory.queryProtection(address).indexOf('r') < 0) return false;
    if (size === 0) return true;
    const last = address.add(size - 1);
    for (let at = address.add(Process.pageSize); at.compare(last) < 0; at = at.add(Process.pageSize))
      if (Memory.queryProtection(at).indexOf('r') < 0) return false;
    return Memory.queryProtection(last).indexOf('r') >= 0;
  } catch (_) { return false; }
}
function allocateTask() {
  const base = Memory.alloc(0x218);
  sender.owned_ranges.push({ base, size: 0x218 });
  base.writeByteArray(new Uint8Array(0x218)); return base;
}
function releaseTaskRange(task) {
  if (task) sender.owned_ranges = sender.owned_ranges.filter(r => !r.base.equals(task));
}
function hex(data) {
  return Array.from(new Uint8Array(data), b => b.toString(16).padStart(2, '0')).join('');
}
function unhex(value) {
  if (typeof value !== 'string' || !value.length || value.length > MAX_WIRE * 2
      || value.length % 2 || !/^[0-9a-fA-F]+$/.test(value)) fail('invalid_text_wire');
  const output = new Uint8Array(value.length / 2);
  for (let i = 0; i < output.length; i++) output[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return output;
}
function utf8(value) {
  if (typeof value !== 'string') fail('invalid_recipient');
  const result = [];
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code >= 0xd800 && code <= 0xdfff) fail('invalid_utf8');
    if (code < 0x80) result.push(code);
    else if (code < 0x800) result.push(0xc0 | code >> 6, 0x80 | code & 63);
    else if (code < 0x10000) result.push(0xe0 | code >> 12, 0x80 | code >> 6 & 63, 0x80 | code & 63);
    else result.push(0xf0 | code >> 18, 0x80 | code >> 12 & 63, 0x80 | code >> 6 & 63, 0x80 | code & 63);
  }
  return new Uint8Array(result);
}
function validUtf8(bytes) {
  for (let i = 0; i < bytes.length;) {
    const lead = bytes[i++];
    if (lead === 0) return false;
    if (lead < 0x80) continue;
    let n, value, min;
    if (lead >= 0xc2 && lead <= 0xdf) { n = 1; value = lead & 31; min = 0x80; }
    else if (lead >= 0xe0 && lead <= 0xef) { n = 2; value = lead & 15; min = 0x800; }
    else if (lead >= 0xf0 && lead <= 0xf4) { n = 3; value = lead & 7; min = 0x10000; }
    else return false;
    if (i + n > bytes.length) return false;
    while (n--) { const byte = bytes[i++]; if ((byte & 0xc0) !== 0x80) return false; value = value * 64 + (byte & 63); }
    if (value < min || value > 0x10ffff || value >= 0xd800 && value <= 0xdfff) return false;
  }
  return true;
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// BigInt preserves all protobuf uint64 values, including native envelope field1.
// Only bounded protocol scalars are converted to Number; identity never is.
function varint(value) {
  let integer = BigInt(value);
  if (integer < 0n || integer > 0xffffffffffffffffn) fail('protobuf_integer_bounds');
  const output = [];
  while (integer >= 128n) { output.push(Number(integer & 127n) | 128); integer >>= 7n; }
  output.push(Number(integer)); return output;
}
function protobuf(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 1024 * 1024) fail('protobuf_bounds');
  let position = 0;
  function takeVarint() {
    let result = 0n;
    for (let i = 0; i < 10; i++) {
      if (position >= bytes.length) fail('protobuf_truncated');
      const value = bytes[position++];
      if (i === 9 && value > 1) fail('protobuf_overflow');
      result |= BigInt(value & 127) << BigInt(i * 7);
      if (!(value & 128)) return result;
    }
    fail('protobuf_overflow');
  }
  const fields = [];
  while (position < bytes.length) {
    if (fields.length >= 64) fail('protobuf_field_limit');
    const tag = takeVarint();
    if (tag < 8n || tag > 0xffffffffn) fail('protobuf_tag');
    const number = Number(tag >> 3n), wire = Number(tag & 7n);
    if (wire === 0) fields.push({ number, wire, value: takeVarint() });
    else if (wire === 2) {
      const bigLength = takeVarint();
      if (bigLength > BigInt(bytes.length - position)) fail('protobuf_field_bounds');
      const length = Number(bigLength);
      fields.push({ number, wire, bytes: bytes.subarray(position, position + length) });
      position += length;
    } else if (wire === 1 || wire === 5) {
      const length = wire === 1 ? 8 : 4;
      if (position + length > bytes.length) fail('protobuf_field_bounds');
      fields.push({ number, wire }); position += length;
    } else fail('protobuf_wire_type');
  }
  return fields;
}
function one(fields, number, wire) {
  const matches = fields.filter(f => f.number === number);
  if (matches.length !== 1 || matches[0].wire !== wire) fail('protobuf_schema');
  return matches[0];
}
function validateText(bytes, recipient) {
  const outer = protobuf(bytes);
  if (outer.length !== 2 || one(outer, 1, 0).value !== 1n) fail('invalid_text_schema');
  const body = protobuf(one(outer, 2, 2).bytes);
  if (body.length !== 6) fail('invalid_text_schema');
  const to = protobuf(one(body, 1, 2).bytes);
  if (to.length !== 1 || !equalBytes(one(to, 1, 2).bytes, utf8(recipient))) fail('recipient_mismatch');
  const content = one(body, 2, 2).bytes;
  if (!content.length || content.length > 4096 || !validUtf8(content)) fail('invalid_text_content');
  if (one(body, 3, 0).value !== 1n) fail('invalid_text_schema');
  const timestamp = one(body, 4, 0).value;
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (timestamp < now - 120n || timestamp > now + 30n) fail('stale_text_timestamp');
  const clientId = one(body, 5, 0).value;
  // Current 4.1.15 field5 is uint32: the native writer at 0x465d0d4
  // loads w1 and invokes the uint32 encoder. The old int64/35-bit template
  // is incompatible with that schema and must not reach native transport.
  if (clientId < 1n || clientId > 0xffffffffn) fail('invalid_client_id');
  if (!equalBytes(one(body, 6, 2).bytes, utf8(SOURCE_XML))) fail('invalid_message_source');
  return { client_id: clientId, timestamp, recipient: utf8(recipient) };
}
function envelope(raw, identity) {
  return new Uint8Array([8, ...varint(BigInt(identity.toString())), 18,
    ...varint(raw.length), ...raw, 24, 0, 32, 0]);
}
function bufferBytes(buffer, maximum) {
  if (!readable(buffer, 40)) fail('response_buffer_shape');
  const length = buffer.add(16).readU64();
  const position = buffer.add(8).readU64(), capacity = buffer.add(24).readU64();
  if (length.compare(maximum) > 0 || position.compare(length) > 0 || capacity.compare(length) < 0)
    fail('response_buffer_bounds');
  const count = length.toNumber(), data = buffer.readPointer();
  if (count && !readable(data, count)) fail('response_buffer_unreadable');
  return count ? new Uint8Array(data.readByteArray(count)) : new Uint8Array(0);
}
function responseEvidence(buffer, expectedRequest) {
  const bytes = bufferBytes(buffer, 1024 * 1024);
  if (!bytes.length) return { response_present: false, server_ret_present: false };
  const outer = protobuf(bytes);
  if (one(outer, 1, 0).value !== 522n) fail('response_command_mismatch');
  const raw = one(outer, 2, 2).bytes;
  const decoded = protobuf(raw), base = protobuf(one(decoded, 1, 2).bytes);
  const ret = one(base, 1, 0).value;
  const decodeErrors = outer.filter(f => f.number === 5);
  if (decodeErrors.length > 1 || decodeErrors.length === 1 && decodeErrors[0].wire !== 0)
    fail('response_decode_schema');
  const result = { response_present: true, server_ret_present: true,
    server_ret: Number(BigInt.asIntN(32, ret)),
    server_ret_zero: ret === 0n,
    native_decode_error_present: decodeErrors.length === 1,
    native_decode_error: decodeErrors.length ? Number(BigInt.asIntN(32, decodeErrors[0].value)) : null,
    native_decode_error_zero: decodeErrors.length ? decodeErrors[0].value === 0n : null,
    message_ret_present: false, message_ret: null, message_ret_zero: false, server_id_present: false,
    server_id_nonzero: false, server_id: null,
    response_field4_present: false, response_field4_matches_request_client_id: false,
    response_recipient_present: false, response_recipient_matches: false,
    response_timestamp_present: false, response_timestamp_matches: false,
    client_id_correlation_verified: false, message_correlated: false };
  const items = decoded.filter(f => f.number === 3);
  result.response_item_count = items.length;
  // This sender submits exactly one text. Absent or multiple response items
  // cannot be implicitly correlated with that text.
  if (items.length !== 1 || items[0].wire !== 2) return result;
  const fields = protobuf(items[0].bytes);
  const returns = fields.filter(f => f.number === 1), serverIds = fields.filter(f => f.number === 8);
  // Current native consumer 0x30bdd08 branches on this signed int32 result;
  // its zero branch sets send state2 and copies field8 as the server message ID.
  if (returns.length === 1 && returns[0].wire === 0) {
    result.message_ret_present = true; result.message_ret = Number(BigInt.asIntN(32, returns[0].value));
    result.message_ret_zero = returns[0].value === 0n;
  }
  if (serverIds.length === 1 && serverIds[0].wire === 0) {
    result.server_id_present = true; result.server_id_nonzero = serverIds[0].value !== 0n;
    result.server_id = serverIds[0].value.toString();
  }
  const field4 = fields.filter(f => f.number === 4);
  if (field4.length === 1 && field4[0].wire === 0) {
    result.response_field4_present = true;
    result.response_field4_matches_request_client_id = !!expectedRequest
      && typeof expectedRequest.client_id === 'bigint' && field4[0].value <= 0xffffffffn
      && field4[0].value === expectedRequest.client_id;
  }
  // Exact v2 observation correlated field4 to the submitted uint32 client ID,
  // field5 to the requested timestamp, and field2 to the recipient WxString.
  // Require all three; a successful result for some other item cannot qualify.
  result.client_id_correlation_verified = result.response_field4_matches_request_client_id;
  const recipients = fields.filter(f => f.number === 2), timestamps = fields.filter(f => f.number === 5);
  if (recipients.length === 1 && recipients[0].wire === 2) {
    result.response_recipient_present = true;
    try {
      const wrapped = protobuf(recipients[0].bytes), recipient = one(wrapped, 1, 2).bytes;
      result.response_recipient_matches = wrapped.length === 1 && !!expectedRequest
        && expectedRequest.recipient instanceof Uint8Array && equalBytes(recipient, expectedRequest.recipient);
    } catch (_) { /* Malformed or duplicate recipient fields cannot correlate. */ }
  }
  if (timestamps.length === 1 && timestamps[0].wire === 0) {
    result.response_timestamp_present = true;
    result.response_timestamp_matches = !!expectedRequest && typeof expectedRequest.timestamp === 'bigint'
      && timestamps[0].value <= 0xffffffffn && timestamps[0].value === expectedRequest.timestamp;
  }
  result.message_correlated = result.client_id_correlation_verified
    && result.response_recipient_matches && result.response_timestamp_matches;
  return result;
}
function publicResult(operation) { return Object.assign({}, operation.result); }
function getresult(operationId) {
  const operation = sender.operations.get(operationId);
  return operation ? publicResult(operation) : { status: 'not_found', operation_id: operationId };
}
function status() {
  const inflight = sender.active === null ? 0 : 1;
  return {
    phase: sender.phase,
    ready: enabled() && sender.prepared && !sender.preparing && inflight === 0
      && !sender.start_in_progress && !sender.callback_depth
      && sender.operations.size < MAX_OPERATIONS && !sender.native_failures,
    armed: !!sender.permit && sender.permit.expires > Date.now(),
    sends_enabled: enabled(),
    diagnostic_code: sender.diagnostic_code || (!enabled() ? 'experimental_sending_not_approved' : null),
    inflight_count: inflight,
    // A JS callback returning is not proof its native trampoline has returned.
    // This finite trial keeps all dispatch code alive until WeChat exits.
    can_detach: !sender.pinned && !sender.preparing && inflight === 0
      && !sender.start_in_progress && !sender.callback_depth,
    lifetime_policy: sender.pinned ? 'pinned_until_app_exit' : 'not_pinned',
    completed_count: sender.completed, operation_capacity_remaining: MAX_OPERATIONS - sender.operations.size,
    lifecycle_smoke: sender.smoke,
    completion_policy: 'correlated_server_acknowledgment_no_delivery_claim',
    outgoing_local_history_reconciled: false
  };
}
function identifyModule() {
  if (Process.arch !== 'arm64' || Process.pointerSize !== 8) fail('unsupported_arch');
  const found = Process.enumerateModules().filter(m => m.name === 'wechat.dylib'
    && m.path.endsWith('/Contents/Resources/wechat.dylib') && m.size > 50 * 1024 * 1024);
  if (found.length !== 1) fail('native_module_not_found');
  if (String(PROFILE.wechat_version) !== '4.1.15' || String(PROFILE.bundle_version) !== '270135'
      || PROFILE.task_size !== 0x218) fail('unsupported_profile');
  return found[0];
}
function setupFunctions() {
  const module = identifyModule(), addresses = {};
  const entries = {
    taskCtor: ['void', ['pointer']], taskDtor: ['void', ['pointer']],
    startTask: ['bool', ['pointer']], stringAssign: ['pointer', ['pointer', 'pointer']],
    wrapperAutoBufferAppend: ['void', ['pointer', 'pointer', 'ulong']],
    wrapperAppSessionGetter: ['pointer', []],
    wrapperEnvelopeIdentityGetter: ['uint64', ['pointer']],
    wrapperDynamicAuthPredicate: ['bool', ['pointer', 'uint32']],
    wrapperAppOnTaskEnd: null
  };
  for (const name of Object.keys(entries)) {
    const offset = PROFILE.offsets[name], expected = PROFILE.expected_bytes[name];
    if (typeof offset !== 'string' || !/^0x[0-9a-f]+$/i.test(offset)
        || typeof expected !== 'string' || !/^(?:[0-9a-f]{2}){8,}$/i.test(expected)) fail('missing_native_profile');
    const address = module.base.add(offset), range = Process.findRangeByAddress(address);
    if (!range || range.protection.indexOf('x') < 0) fail('native_address_not_executable');
    // A separately verified passive session may already hook only startTask.
    // Normal single-host startup has no such hook and verifies every prefix.
    const verifiedPassiveStart = name === 'startTask' && PROFILE.start_task_passive_hook_verified === true;
    if (!verifiedPassiveStart && hex(address.readByteArray(expected.length / 2)) !== expected.toLowerCase())
      fail('native_instruction_mismatch');
    addresses[name] = address;
  }
  const native = {};
  for (const name of Object.keys(entries)) if (entries[name]) {
    native[name] = new NativeFunction(addresses[name], entries[name][0], entries[name][1],
      { scheduling: 'cooperative' });
  }
  sender.module = module; sender.addresses = addresses; sender.native = native;
}
function account() {
  const session = sender.native.wrapperAppSessionGetter();
  if (!readable(session, 8)) fail('account_not_ready');
  const identity = sender.native.wrapperEnvelopeIdentityGetter(session);
  if (identity.compare(0) === 0) fail('account_not_ready');
  if (sender.account_identity !== null && identity.compare(sender.account_identity) !== 0)
    fail('prepared_account_changed');
  if (sender.native.wrapperDynamicAuthPredicate(session, 522)) fail('dynamic_auth_not_supported');
  return { session, identity };
}
function checkEmptyTask(task) {
  if (!task.readU32() || task.add(0x1c0).readU8() !== 0
      || !task.add(0x58).readPointer().isNull()
      || bufferBytes(task.add(0x1c8), MAX_WIRE).length
      || bufferBytes(task.add(0x1f0), MAX_WIRE).length) fail('native_task_defaults_mismatch');
}
function complete(_self, taskId, context, _userId, errorType, errorCode, _profile, response) {
  sender.callback_depth++;
  try {
    const operation = sender.byTask.get(taskId);
    // The machine-code dispatcher already checked this pair. Keep a second
    // check; never invoke an app handler with a fabricated user_context.
    if (!operation || !context.equals(operation.context)) {
      sender.native_failures++; sender.diagnostic_code = 'completion_ownership_mismatch'; return 0;
    }
    if (operation.completed) return 0;
    const evidence = { task_error_type: errorType, task_error_code: errorCode,
      server_ret_present: false, message_ret_present: false };
    try { Object.assign(evidence, responseEvidence(response, operation.sent_metadata)); }
    catch (_) { evidence.response_parse_valid = false; }
    const responseGood = errorType === 0 && errorCode === 0 && evidence.server_ret_present
      && evidence.server_ret_zero && evidence.message_ret_present && evidence.message_ret_zero
      && evidence.server_id_present && evidence.server_id_nonzero
      && evidence.message_correlated
      && (!evidence.native_decode_error_present || evidence.native_decode_error_zero);
    operation.result = Object.assign(operation.result, evidence, {
      status: responseGood ? 'acknowledged' : 'outcome_unknown', completed: true,
      diagnostic_code: responseGood ? 'server_acknowledged' : 'native_completion_unconfirmed'
    });
    operation.completed = true; sender.completed++;
    if (sender.active === operation) sender.active = null;
    sender.phase = 'prepared';
    // The routing record and token remain alive for late/duplicate completions.
    // No chat content, recipient, identity, auth bytes or native pointers escape.
    send(Object.assign({ type: 'ack' }, publicResult(operation)));
    return 0;
  } catch (_) {
    sender.native_failures++; sender.diagnostic_code = 'completion_handler_failed';
    return 0;
  } finally { sender.callback_depth--; }
}
function installDispatcher() {
  const slots = Memory.alloc(MAX_OPERATIONS * 16);
  slots.writeByteArray(new Uint8Array(MAX_OPERATIONS * 16));
  const originalSlot = Memory.alloc(8); originalSlot.writePointer(ptr(0));
  const callback = new NativeCallback(complete, 'int',
    ['pointer', 'uint32', 'pointer', 'pointer', 'int', 'int', 'pointer', 'pointer']);
  const code = Memory.alloc(Process.pageSize * 2);
  Memory.patchCode(code, Process.pageSize * 2, writable => {
    const writer = new Arm64Writer(writable, { pc: code });
    for (let i = 0; i < MAX_OPERATIONS; i++) {
      const next = 'next_' + i;
      // x16/x17 are ABI scratch registers. All arguments, x8, stack and link
      // register pass through untouched, including any unknown normal ABI data.
      writer.putLdrRegAddress('x16', slots.add(i * 16));
      writer.putLdrRegRegOffset('w17', 'x16', 0);
      writer.putCbzRegLabel('w17', next);
      writer.putCmpRegReg('w1', 'w17'); writer.putBCondLabel('ne', next);
      writer.putLdrRegRegOffset('x17', 'x16', 8);
      writer.putCmpRegReg('x2', 'x17'); writer.putBCondLabel('ne', next);
      writer.putLdrRegAddress('x17', callback); writer.putBrReg('x17');
      writer.putLabel(next);
    }
    writer.putLdrRegAddress('x16', originalSlot);
    writer.putLdrRegRegOffset('x17', 'x16', 0); writer.putBrReg('x17');
    writer.flush(); writer.dispose();
  });
  if (!Memory.protect(code, Process.pageSize * 2, 'r-x')) fail('dispatcher_not_executable');
  if (typeof Memory.queryProtection !== 'function'
      || Memory.queryProtection(code).indexOf('x') < 0
      || Memory.queryProtection(code.add(Process.pageSize * 2 - 1)).indexOf('x') < 0)
    fail('dispatcher_not_executable');
  // Do not attempt runtime unload after replacement: even an unrelated native
  // thread may still be traversing the dispatcher. Process exit releases it.
  Script.pin(); sender.pinned = true;
  // Frida batches interceptor changes until leaving JS/flush. Publish the
  // returned original trampoline before flushing or making another native call.
  const original = Interceptor.replaceFast(sender.addresses.wrapperAppOnTaskEnd, code);
  originalSlot.writePointer(original);
  sender.dispatch = { slots, originalSlot, callback, code, original };
  Interceptor.flush();
}
function prepare() {
  if (sender.prepared || sender.preparing || sender.active || sender.pinned) return status();
  sender.preparing = true; sender.phase = 'preparing';
  let task = null, constructed = false;
  try {
    setupFunctions();
    const initialIdentity = account().identity;
    task = allocateTask();
    sender.native.taskCtor(task); constructed = true;
    checkEmptyTask(task);
    sender.native.taskDtor(task); constructed = false;
    sender.smoke = { constructed: true, defaults_valid: true, destroyed: true,
      account_ready: true, dynamic_auth_522: false };
    if (account().identity.compare(initialIdentity) !== 0) fail('account_changed_during_prepare');
    installDispatcher();
    // Private equality guard only. Never serialize or log this native identity.
    // Failed pre-account-ready attempts leave it unset and remain retriable.
    sender.account_identity = initialIdentity;
    sender.prepared = true; sender.phase = 'prepared'; sender.diagnostic_code = null;
  } catch (error) {
    sender.phase = 'blocked'; sender.diagnostic_code = safeError(error, 'native_prepare_failed');
  } finally {
    if (constructed) {
      try { sender.native.taskDtor(task); }
      catch (_) { sender.native_failures++; sender.diagnostic_code = 'native_destructor_failed'; }
    }
    if (!sender.native_failures) releaseTaskRange(task);
    sender.preparing = false;
  }
  return status();
}
function disarm() { sender.permit = null; return { armed: false }; }
function arm(options) {
  sender.permit = null;
  if (!enabled()) return { armed: false, diagnostic_code: 'experimental_sending_not_approved' };
  if (!status().ready) return { armed: false, diagnostic_code: 'native_sender_not_ready' };
  try {
    const recipient = options && options.recipient, bytes = utf8(recipient);
    if (!bytes.length || bytes.length > 512 || !validUtf8(bytes)) fail('invalid_recipient');
    const seconds = options.ttl_seconds === undefined ? 60 : options.ttl_seconds;
    if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 60) fail('invalid_arm_ttl');
    account();
    sender.permit = { recipient, expires: Date.now() + seconds * 1000 };
    return { armed: true, ttl_seconds: seconds };
  } catch (error) { return { armed: false, diagnostic_code: safeError(error, 'arm_failed') }; }
}
function sendtext(_legacyTaskId, protoHex, operationId) {
  const permit = sender.permit; sender.permit = null;
  if (typeof operationId !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{7,127}$/.test(operationId))
    return { status: 'rejected', diagnostic_code: 'invalid_operation_id' };
  if (sender.operations.has(operationId)) return getresult(operationId);
  if (!enabled()) return { status: 'rejected', operation_id: operationId, diagnostic_code: 'experimental_sending_not_approved' };
  if (!status().ready) return { status: 'rejected', operation_id: operationId, diagnostic_code: 'native_sender_not_ready' };
  if (!permit || permit.expires < Date.now()) return { status: 'rejected', operation_id: operationId, diagnostic_code: 'one_use_authorization_required' };
  let task = null, constructed = false, operation = null, attempted = false;
  sender.start_in_progress = true;
  try {
    const raw = unhex(protoHex), textMetadata = validateText(raw, permit.recipient);
    const identity = account().identity, packed = envelope(raw, identity);
    task = allocateTask();
    sender.native.taskCtor(task); constructed = true; checkEmptyTask(task);
    const taskId = task.readU32();
    if (sender.byTask.has(taskId)) fail('native_task_id_collision');
    const context = Memory.alloc(8); context.writeU64(0);
    task.add(4).writeU32(522); task.add(0x10).writeU32(1); task.add(0x31).writeU8(1);
    task.add(0x40).writeS32(1); task.add(0x58).writePointer(context); task.add(0x60).writeU64(522);
    const cgi = Memory.allocUtf8String(CGI);
    sender.native.stringAssign(task.add(0x18), cgi);
    const data = Memory.alloc(packed.length); data.writeByteArray(packed);
    sender.native.wrapperAutoBufferAppend(task.add(0x1c8), data, packed.length);
    task.add(0x1c0).writeU8(1);
    if (!equalBytes(bufferBytes(task.add(0x1c8), MAX_WIRE), packed)) fail('native_buffer_copy_mismatch');
    operation = { context, sent_metadata: textMetadata, completed: false,
      result: { status: 'submitted', operation_id: operationId,
      task_id: taskId, completed: false, diagnostic_code: 'native_submission_pending' } };
    const slot = sender.dispatch.slots.add(sender.operations.size * 16);
    sender.operations.set(operationId, operation); sender.byTask.set(taskId, operation);
    sender.active = operation; sender.phase = 'inflight';
    // Context is initialized before publishing a nonzero native-owned ID.
    slot.add(8).writePointer(context); slot.writeU32(taskId);
    // A final read-only auth/session check closes the construction interval.
    if (account().identity.compare(identity) !== 0) fail('account_changed_during_prepare');
    attempted = true;
    const accepted = sender.native.startTask(task);
    if (!operation.completed) {
      operation.result.status = accepted ? 'submitted' : 'outcome_unknown';
      operation.result.diagnostic_code = accepted ? 'native_task_submitted' : 'native_start_not_confirmed';
    }
  } catch (error) {
    const code = safeError(error, attempted ? 'native_submission_uncertain' : 'native_preflight_failed');
    if (operation) {
      if (!operation.completed) {
        operation.result.status = attempted ? 'outcome_unknown' : 'rejected'; operation.result.diagnostic_code = code;
        if (!attempted) {
          operation.completed = true; operation.result.completed = true;
          sender.active = null; sender.phase = 'prepared';
        }
      }
    } else return { status: 'rejected', operation_id: operationId, diagnostic_code: code };
  } finally {
    if (constructed) {
      try { sender.native.taskDtor(task); }
      catch (_) { sender.native_failures++; sender.diagnostic_code = 'native_destructor_failed'; }
    }
    if (!sender.native_failures) releaseTaskRange(task);
    sender.start_in_progress = false;
  }
  return publicResult(operation);
}

rpc.exports = { prepare, status, arm, disarm, sendtext, getresult };
