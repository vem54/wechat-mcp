/* SPDX-License-Identifier: GPL-3.0-only
 * Passive, one-message diagnostic extension. No NativeFunction, replacement,
 * writes to app memory, request construction or send functionality.
 * The host supplies exact-build PROFILE. select() selects a known File Helper
 * marker; no other message body, recipient, key or identity is retained/emitted.
 */
'use strict';
const EXPECTED_CGI = '/cgi-bin/micromsg-bin/newsendmsg';
const EXPECTED_SOURCE = '<msgsource><alnode><fr>1</fr></alnode></msgsource>';
const diagnostic = { phase: 'waiting_module', diagnostic_code: null, module: null,
  config: null, selected: null, request: null, response: null, completion: null,
  selected_at: null, trace_until: 0, command_window: [], command_window_truncated: false,
  listeners: [], prepThreads: new Map(), counts: { matching_starts: 0, matching_ends: 0 } };

function readable(address, size) {
  if (!address || address.isNull() || !Number.isSafeInteger(size) || size < 0 || size > 1024 * 1024) return false;
  const range = Process.findRangeByAddress(address);
  if (range && range.protection.indexOf('r') >= 0
      && address.add(size).compare(range.base.add(range.size)) <= 0) return true;
  try {
    if (Memory.queryProtection(address).indexOf('r') < 0) return false;
    if (!size) return true;
    const last = address.add(size - 1);
    for (let at = address.add(Process.pageSize); at.compare(last) < 0; at = at.add(Process.pageSize))
      if (Memory.queryProtection(at).indexOf('r') < 0) return false;
    return Memory.queryProtection(last).indexOf('r') >= 0;
  } catch (_) { return false; }
}
function encode(value) {
  const result = [];
  for (const char of value) {
    const c = char.codePointAt(0);
    if (c >= 0xd800 && c <= 0xdfff) throw Error('invalid_marker');
    if (c < 128) result.push(c);
    else if (c < 2048) result.push(0xc0 | c >> 6, 0x80 | c & 63);
    else if (c < 65536) result.push(0xe0 | c >> 12, 0x80 | c >> 6 & 63, 0x80 | c & 63);
    else result.push(0xf0 | c >> 18, 0x80 | c >> 12 & 63, 0x80 | c >> 6 & 63, 0x80 | c & 63);
  }
  return result;
}
function matches(data, length, bytes) {
  if (length !== bytes.length || !readable(data, length)) return false;
  for (let i = 0; i < length; i++) if (data.add(i).readU8() !== bytes[i]) return false;
  return true;
}
function contains(data, length, bytes) {
  if (length > 4096 || !readable(data, length)) return false;
  for (let i = 0; i <= length - bytes.length; i++) {
    let same = true;
    for (let j = 0; j < bytes.length; j++) if (data.add(i + j).readU8() !== bytes[j]) { same = false; break; }
    if (same) return true;
  }
  return false;
}
function buffer(address) {
  if (!readable(address, 40)) throw Error('buffer_shape');
  const length = address.add(16).readU64(), position = address.add(8).readU64(), capacity = address.add(24).readU64();
  if (length.compare(1024 * 1024) > 0 || position.compare(length) > 0 || capacity.compare(length) < 0)
    throw Error('buffer_bounds');
  const size = length.toNumber(), data = address.readPointer();
  if (size && !readable(data, size)) throw Error('buffer_unreadable');
  return { data, length: size };
}
// Read wire headers and selected scalars. Length-delimited private payloads are
// skipped by pointer arithmetic; optional envelope auth fields are never copied.
function scan(data, length, scalarNumbers) {
  if (!readable(data, length)) throw Error('protobuf_bounds');
  let at = 0;
  function vi(accumulate) {
    let value = 0n, zero = true, bits = 0;
    for (let i = 0; i < 10; i++) {
      if (at >= length) throw Error('protobuf_truncated');
      const byte = data.add(at++).readU8(), part = byte & 127;
      if (i === 9 && byte > 1) throw Error('protobuf_overflow');
      if (part) { zero = false; bits = i * 7 + Math.floor(Math.log2(part)) + 1; }
      if (accumulate) value |= BigInt(part) << BigInt(i * 7);
      if (!(byte & 128)) return { value: accumulate ? value : null, zero, bits };
    }
    throw Error('protobuf_overflow');
  }
  const fields = [];
  while (at < length) {
    if (fields.length >= 64) throw Error('protobuf_field_limit');
    const tag = vi(true).value;
    if (tag < 8n || tag > 0xffffffffn) throw Error('protobuf_tag');
    const number = Number(tag >> 3n), wire = Number(tag & 7n), field = { number, wire };
    if (wire === 0) Object.assign(field, vi(scalarNumbers.includes(number)));
    else if (wire === 2) {
      const bigSize = vi(true).value;
      if (bigSize > BigInt(length - at)) throw Error('protobuf_field_bounds');
      field.length = Number(bigSize); field.data = data.add(at); at += field.length;
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4;
      if (at + size > length) throw Error('protobuf_field_bounds');
      at += size;
    } else throw Error('protobuf_wire');
    fields.push(field);
  }
  return fields;
}
function one(fields, number, wire) {
  const found = fields.filter(f => f.number === number && f.wire === wire);
  return found.length === 1 ? found[0] : null;
}
function schema(fields, scalarMetadata) {
  return fields.map(f => {
    const out = { field: f.number, wire: f.wire };
    if (f.wire === 2) out.length = f.length;
    if (f.wire === 0 && scalarMetadata) { out.zero = f.zero; out.unsigned_bits = f.bits; }
    return out;
  });
}
function nativeStringEquals(address, text) {
  if (!readable(address, 24)) return { valid: false, equals_expected: false };
  const tail = address.add(23).readU8();
  const length = tail & 128 ? address.add(8).readU64() : null;
  if (length && length.compare(1024) > 0) return { valid: false, equals_expected: false };
  const count = length ? length.toNumber() : tail;
  if (!(tail & 128) && count > 22) return { valid: false, equals_expected: false };
  const data = tail & 128 ? address.readPointer() : address;
  return { valid: readable(data, count), length: count, equals_expected: matches(data, count, encode(text)) };
}
function codeOffset(address) {
  if (!diagnostic.module || address.compare(diagnostic.module.base) < 0
      || address.compare(diagnostic.module.base.add(diagnostic.module.size)) >= 0) return null;
  const range = Process.findRangeByAddress(address);
  return range && range.protection.includes('x') ? address.sub(diagnostic.module.base).toString() : null;
}
function prepTargets(message) {
  if (!readable(message, 0x78) || message.add(0xc).readU32() !== 522) return null;
  const vtable = message.readPointer();
  if (!readable(vtable, 0x20)) return null;
  return { request_builder_offset: codeOffset(vtable.add(0x10).readPointer()),
    response_parser_offset: codeOffset(vtable.add(0x18).readPointer()) };
}
function envelopeIdentityMatches(field) {
  if (!field || field.value === null) return null;
  try {
    // Exact-build pointer chain independently observed by the host and verified
    // statically: the getter's account leaf only loads this uint64. No native
    // getter is called and no identity value is retained in diagnostic output.
    const slot = diagnostic.module.base.add(0xa45df38);
    if (!readable(slot, 8)) return null;
    const session = slot.readPointer();
    if (!readable(session, 0x70)) return null;
    const account = session.add(0x68).readPointer();
    if (!readable(account, 0x48)) return null;
    return field.value === BigInt(account.add(0x40).readU64().toString());
  } catch (_) { return null; }
}
function request(task, threadId) {
  const config = diagnostic.config;
  if (!config || config.expires < Date.now() || diagnostic.selected
      || !readable(task, 0x218) || task.add(4).readU32() !== 522) return;
  const prepared = buffer(task.add(0x1c8));
  const outer = scan(prepared.data, prepared.length, [1, 3, 4, 8, 9]);
  const raw = one(outer, 2, 2); if (!raw) return;
  const text = scan(raw.data, raw.length, [1]);
  const bodyField = one(text, 2, 2); if (!bodyField) return;
  const body = scan(bodyField.data, bodyField.length, [3, 4, 5]);
  const to = one(body, 1, 2), content = one(body, 2, 2);
  if (!to || !content) return;
  const recipient = one(scan(to.data, to.length, []), 1, 2);
  if (!recipient || !matches(recipient.data, recipient.length, config.recipient)
      || !matches(content.data, content.length, config.marker)) return;
  const clientId = one(body, 5, 0), timestamp = one(body, 4, 0), xml = one(body, 6, 2);
  const taskId = task.readU32();
  if (config.task_id !== null && taskId !== config.task_id) return;
  diagnostic.selected = { task_id: taskId, context: task.add(0x58).readPointer(),
    client_id: clientId ? clientId.value : null, timestamp: timestamp ? timestamp.value : null };
  diagnostic.selected_at = Date.now(); diagnostic.trace_until = diagnostic.selected_at + 5000;
  diagnostic.counts.matching_starts++;
  const now = BigInt(Math.floor(Date.now() / 1000));
  const stack = diagnostic.prepThreads.get(threadId);
  diagnostic.request = {
    selected_marker_matches: true, recipient_is_filehelper: true,
    envelope_identity_equals_current_account: envelopeIdentityMatches(one(outer, 1, 0)),
    cgi: nativeStringEquals(task.add(0x18), EXPECTED_CGI),
    longlink: nativeStringEquals(task.add(0x68), 'default-longlink'),
    task: { channel: task.add(0x10).readU32(), need_authed: task.add(0x31).readU8(),
      prepared_flag: task.add(0x1c0).readU8(), context_equals_command: task.add(0x60).readU64().compare(522) === 0,
      byte_0x30: task.add(0x30).readU8(), byte_0x32: task.add(0x32).readU8(), byte_0x33: task.add(0x33).readU8(),
      scalar_0x38: task.add(0x38).readS32(), scalar_0x3c: task.add(0x3c).readS32(),
      scalar_0x40: task.add(0x40).readS32(), scalar_0x44: task.add(0x44).readS32(),
      scalar_0x48: task.add(0x48).readS32(), byte_0x4c: task.add(0x4c).readU8(), scalar_0x50: task.add(0x50).readS32() },
    envelope_fields: schema(outer, false), text_fields: schema(text, true), body_fields: schema(body, false),
    body_flag_equals_one: !!one(body, 3, 0) && one(body, 3, 0).value === 1n,
    timestamp_within_two_minutes: !!timestamp && timestamp.value >= now - 120n && timestamp.value <= now + 120n,
    client_id_unsigned_bits: clientId ? clientId.bits : null,
    client_id_is_nonzero_uint32: !!clientId && clientId.value >= 1n && clientId.value <= 0xffffffffn,
    source: xml ? { length: xml.length, equals_trial_source: matches(xml.data, xml.length, encode(EXPECTED_SOURCE)),
      has_alnode_tag: contains(xml.data, xml.length, encode('<alnode>')),
      has_atuserlist_tag: contains(xml.data, xml.length, encode('<atuserlist>')) } : null,
    app_message_code: stack && stack.length ? stack[stack.length - 1] : null
  };
  diagnostic.phase = 'matching_text_observed';
}
function recordCommand(task) {
  if (!diagnostic.selected || Date.now() > diagnostic.trace_until || !readable(task, 0x18)) return;
  if (diagnostic.command_window.length >= 80) { diagnostic.command_window_truncated = true; return; }
  diagnostic.command_window.push({ command: task.add(4).readU32(), channel: task.add(0x10).readU32(),
    relative_ms: Date.now() - diagnostic.selected_at, selected_task: task.readU32() === diagnostic.selected.task_id,
    after_selected_completion_enter: diagnostic.completion !== null });
}
function nestedResponseItem(field) {
  const selected = diagnostic.selected;
  const item = scan(field.data, field.length, Array.from({ length: 64 }, (_, i) => i + 1));
  return item.map(f => {
    const output = { field: f.number, wire: f.wire };
    if (f.wire === 0) {
      output.zero = f.zero; output.unsigned_bits = f.bits;
      output.equals_request_client_id = selected.client_id !== null && f.value === selected.client_id;
      output.equals_request_timestamp = selected.timestamp !== null && f.value === selected.timestamp;
    } else if (f.wire === 2) {
      output.length = f.length;
      output.equals_filehelper_utf8 = matches(f.data, f.length, diagnostic.config.recipient);
      // Only report a nested WxString match; never retain arbitrary string data.
      try {
        const nested = scan(f.data, f.length, []), value = one(nested, 1, 2);
        output.equals_filehelper_wxstring = nested.length === 1 && !!value
          && matches(value.data, value.length, diagnostic.config.recipient);
        output.nested_fields = schema(nested, true);
      } catch (_) { output.nested_protobuf = false; }
    }
    return output;
  });
}
function response(address) {
  const prepared = buffer(address);
  const outer = scan(prepared.data, prepared.length, [4, 5]), raw = one(outer, 2, 2);
  if (!raw) return { envelope_fields: schema(outer, false), raw_response_present: false };
  const cgi = scan(raw.data, raw.length, [2, 4]), base = one(cgi, 1, 2);
  const summary = { envelope_fields: schema(outer, false), cgi_fields: schema(cgi, true),
    batch_return_present: false, batch_return_zero: null, response_items: [] };
  if (base) {
    const baseFields = scan(base.data, base.length, [1]), ret = one(baseFields, 1, 0);
    summary.batch_return_present = !!ret; summary.batch_return_zero = ret ? ret.zero : null;
    summary.base_response_fields = schema(baseFields, false);
  }
  for (const field of cgi.filter(f => f.number === 3 && f.wire === 2)) {
    if (summary.response_items.length >= 8) { summary.items_truncated = true; break; }
    try { summary.response_items.push({ valid_wire: true, fields: nestedResponseItem(field) }); }
    catch (_) { summary.response_items.push({ valid_wire: false }); }
  }
  return summary;
}
function status() {
  return { phase: diagnostic.phase, diagnostic_code: diagnostic.diagnostic_code, sends_enabled: false,
    selection_configured: diagnostic.config !== null, counts: Object.assign({}, diagnostic.counts),
    request: diagnostic.request, response: diagnostic.response, completion: diagnostic.completion,
    command_window: diagnostic.command_window.slice(), command_window_truncated: diagnostic.command_window_truncated,
    command_window_elapsed: diagnostic.selected_at !== null && Date.now() > diagnostic.trace_until };
}
function select(options) {
  if (diagnostic.selected && !diagnostic.completion) return { selected: false, diagnostic_code: 'capture_in_progress' };
  if (!options || options.recipient !== 'filehelper' || typeof options.marker !== 'string'
      || !options.marker.trim() || options.marker.includes('\0')) return { selected: false, diagnostic_code: 'invalid_selection' };
  try {
    const marker = encode(options.marker);
    if (marker.length > 512) throw Error('invalid_marker');
    const taskId = options.task_id === undefined ? null : options.task_id;
    if (taskId !== null && (!Number.isInteger(taskId) || taskId <= 0 || taskId > 0xffffffff)) throw Error('invalid_task_id');
    diagnostic.config = { marker, recipient: encode('filehelper'), task_id: taskId, expires: Date.now() + 10 * 60 * 1000 };
    diagnostic.selected = null; diagnostic.request = null; diagnostic.response = null; diagnostic.completion = null;
    diagnostic.selected_at = null; diagnostic.trace_until = 0;
    diagnostic.command_window = []; diagnostic.command_window_truncated = false;
    diagnostic.diagnostic_code = null;
    diagnostic.phase = diagnostic.module ? 'waiting_for_matching_text' : 'waiting_module';
    return { selected: true, sends_enabled: false, expires_in_seconds: 600 };
  } catch (_) { return { selected: false, diagnostic_code: 'invalid_selection' }; }
}
function initialize(module) {
  if (diagnostic.module || module.name !== 'wechat.dylib'
      || !module.path.endsWith('/Contents/Resources/wechat.dylib') || module.size < 50 * 1024 * 1024) return;
  try {
    if (Process.arch !== 'arm64' || String(PROFILE.wechat_version) !== '4.1.15'
        || String(PROFILE.bundle_version) !== '270135') throw Error('unsupported_profile');
    diagnostic.module = module;
    const address = name => module.base.add(PROFILE.offsets[name]);
    for (const name of ['startTask', 'onTaskEnd', 'wrapperAppPrepareTask'])
      if (!PROFILE.offsets[name] || codeOffset(address(name)) === null) throw Error('invalid_profile_address');
    // Native start/end are already observed by the first passive script; verify
    // the newly attached app-preparation entry against its unchanged bytes.
    const expected = PROFILE.expected_bytes.wrapperAppPrepareTask;
    const actual = Array.from(new Uint8Array(address('wrapperAppPrepareTask').readByteArray(expected.length / 2)),
      b => b.toString(16).padStart(2, '0')).join('');
    if (actual !== expected.toLowerCase()) throw Error('app_preparation_bytes_mismatch');
    diagnostic.listeners.push(Interceptor.attach(address('wrapperAppPrepareTask'), {
      onEnter(args) {
        this.stacked = false;
        if (!diagnostic.config || diagnostic.selected) return;
        try {
          const targets = prepTargets(args[1]); if (!targets) return;
          const stack = diagnostic.prepThreads.get(this.threadId) || [];
          stack.push(targets); diagnostic.prepThreads.set(this.threadId, stack); this.stacked = true;
        } catch (_) { /* No app-object pointer or payload is retained. */ }
      },
      onLeave() {
        if (!this.stacked) return;
        const stack = diagnostic.prepThreads.get(this.threadId);
        if (stack) { stack.pop(); if (!stack.length) diagnostic.prepThreads.delete(this.threadId); }
      }
    }));
    diagnostic.listeners.push(Interceptor.attach(address('startTask'), { onEnter(args) {
      try { request(args[0], this.threadId); recordCommand(args[0]); }
      catch (_) { diagnostic.diagnostic_code = 'request_diagnostic_unverified'; }
    }}));
    diagnostic.listeners.push(Interceptor.attach(address('onTaskEnd'), { onEnter(args) {
      this.selectedCompletion = false;
      const selected = diagnostic.selected;
      if (!selected || args[1].toUInt32() !== selected.task_id || !args[2].equals(selected.context)) return;
      diagnostic.counts.matching_ends++;
      this.selectedCompletion = true;
      diagnostic.completion = { error_type_zero: args[4].toInt32() === 0, error_code_zero: args[5].toInt32() === 0,
        exact_task_context_matches: true, relative_ms: Date.now() - diagnostic.selected_at,
        native_bridge_returned: false };
      try { diagnostic.response = response(args[7]); }
      catch (_) { diagnostic.diagnostic_code = 'response_diagnostic_unverified'; }
      diagnostic.phase = 'matching_text_completed';
    }, onLeave() {
      if (this.selectedCompletion && diagnostic.completion) diagnostic.completion.native_bridge_returned = true;
    }}));
    diagnostic.phase = diagnostic.config ? 'waiting_for_matching_text' : 'waiting_selection';
  } catch (_) {
    for (const listener of diagnostic.listeners) listener.detach();
    diagnostic.listeners = []; diagnostic.phase = 'blocked'; diagnostic.diagnostic_code = 'probe_initialization_failed';
  }
}
rpc.exports = { select, status };
const observer = Process.attachModuleObserver({ onAdded: initialize });
