/* SPDX-License-Identifier: GPL-3.0-only
 * Second, passive script for one naturally occurring outgoing text task.
 * No message is sent, changed, constructed, or intercepted for replacement.
 * Wire scanning reads headers only and skips message/key/auth byte payloads.
 * PROFILE is supplied by the host after exact code hash verification.
 */
'use strict';

const probe = { phase: 'waiting_module', diagnostic_code: null, initialized: false,
  selected: null, request: null, response: null, completion: null,
  counts: { text_starts: 0, response_observations: 0, matching_ends: 0 },
  auth: { calls_522: 0, true_results: 0, false_results: 0, last_result: null },
  listeners: [] };

function readable(address, size) {
  if (!address || address.isNull() || !Number.isSafeInteger(size) || size < 0) return false;
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('r') >= 0
    && address.add(size).compare(range.base.add(range.size)) <= 0;
}
function executable(address) {
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('x') >= 0;
}
function toHex(data) {
  return Array.from(new Uint8Array(data), b => b.toString(16).padStart(2, '0')).join('');
}
function getBuffer(buffer) {
  if (!readable(buffer, 40)) throw new Error('buffer_shape');
  const length = buffer.add(16).readU64().toNumber();
  const position = buffer.add(8).readU64().toNumber();
  const capacity = buffer.add(24).readU64().toNumber();
  const data = buffer.readPointer();
  if (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024
      || !Number.isSafeInteger(position) || position < 0 || position > length
      || !Number.isSafeInteger(capacity) || capacity < length
      || (length && !readable(data, length))) throw new Error('buffer_bounds');
  return { data: data, length: length };
}

// Returned addresses are transient and never leave the scanner's callers.
// Unknown varints are skipped without accumulating their identifier values.
function scan(data, length, scalarFields) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024
      || (length && !readable(data, length))) throw new Error('protobuf_bounds');
  let position = 0;
  function varint(accumulate) {
    let value = 0, factor = 1, zero = true;
    for (let i = 0; i < 10; i++) {
      if (position >= length) throw new Error('truncated_varint');
      const byte = data.add(position++).readU8(), bits = byte & 127;
      if (i === 9 && byte > 1) throw new Error('varint_overflow');
      zero = zero && bits === 0;
      if (accumulate) {
        value += bits * factor;
        if (!Number.isSafeInteger(value)) throw new Error('integer_overflow');
      }
      if (!(byte & 128)) return { value: accumulate ? value : null, zero: zero };
      factor *= 128;
    }
    throw new Error('varint_overflow');
  }
  const fields = [];
  while (position < length) {
    if (fields.length >= 64) throw new Error('field_limit');
    const tag = varint(true).value, number = Math.floor(tag / 8), wire = tag & 7;
    if (!number || number > 0x1fffffff) throw new Error('invalid_tag');
    const field = { number: number, wire: wire };
    if (wire === 0) {
      const safe = scalarFields.indexOf(number) !== -1;
      const scalar = varint(safe);
      field.zero = scalar.zero;
      if (safe) field.scalar = scalar.value;
    } else if (wire === 2) {
      const size = varint(true).value;
      if (size > length - position) throw new Error('field_bounds');
      field.data = data.add(position); field.length = size;
      position += size; // Skip the payload without reading its bytes.
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4;
      if (size > length - position) throw new Error('fixed_bounds');
      position += size;
    } else throw new Error('unsupported_wire');
    fields.push(field);
  }
  return fields;
}
function field(fields, number, wire) {
  const found = fields.filter(f => f.number === number && f.wire === wire);
  return found.length === 1 ? found[0] : null;
}
function shape(fields, lengthFields) {
  return fields.map(f => {
    const out = { field: f.number, wire: f.wire };
    if (f.length !== undefined && lengthFields.indexOf(f.number) !== -1) out.length = f.length;
    if (f.scalar !== undefined) out.value = f.scalar;
    return out;
  });
}
function requestSummary(task) {
  const buffer = getBuffer(task.add(0x1c8));
  const envelope = scan(buffer.data, buffer.length, [3, 4, 8, 9, 12, 13]);
  const summary = { command: 522, channel: task.add(0x10).readU32(),
    prepared_flag: task.add(0x1c0).readU8(),
    need_authed: task.add(0x31).readU8(),
    scalar_offset_0x40: task.add(0x40).readS32(),
    context_equals_command: task.add(0x60).readU64().compare(522) === 0,
    envelope: { valid: true, fields: shape(envelope, [2]) } };
  const raw = field(envelope, 2, 2);
  if (raw) {
    const text = scan(raw.data, raw.length, [1]);
    summary.text_request = { fields: shape(text, [2]) };
    const bodyField = field(text, 2, 2);
    if (bodyField) {
      const body = scan(bodyField.data, bodyField.length, [3]);
      summary.text_request.body_fields = shape(body, [1, 2, 6]);
      const recipient = field(body, 1, 2);
      if (recipient) summary.text_request.recipient_fields = shape(scan(recipient.data, recipient.length, []), [1]);
      summary.text_request.expected_schema = !!field(text, 1, 0)
        && field(text, 1, 0).scalar === 1 && !!field(body, 2, 2)
        && !!field(body, 3, 0) && field(body, 3, 0).scalar === 1
        && !!field(body, 4, 0) && !!field(body, 5, 0) && !!field(body, 6, 2);
    }
  }
  return summary;
}
function responseSummary(bufferAddress, source) {
  const buffer = getBuffer(bufferAddress);
  if (!buffer.length) return null;
  const envelope = scan(buffer.data, buffer.length, []);
  const summary = { source: source, envelope: { valid: true, fields: shape(envelope, [2]) },
    cgi_return_code_present: false, cgi_return_code_zero: null };
  const raw = field(envelope, 2, 2);
  if (raw) {
    const cgi = scan(raw.data, raw.length, []);
    summary.cgi_fields = shape(cgi, []);
    const base = field(cgi, 1, 2);
    if (base) {
      const baseFields = scan(base.data, base.length, []), code = field(baseFields, 1, 0);
      summary.base_response_fields = shape(baseFields, []);
      summary.cgi_return_code_present = code !== null;
      summary.cgi_return_code_zero = code ? code.zero : null;
    }
  }
  return summary;
}
function status() {
  return { phase: probe.phase, diagnostic_code: probe.diagnostic_code,
    sends_enabled: false, captures_one_text_task: true,
    counts: Object.assign({}, probe.counts), auth: Object.assign({}, probe.auth),
    request: probe.request, response: probe.response, completion: probe.completion };
}
function initialize(module) {
  if (probe.initialized || module.name !== 'wechat.dylib'
      || !module.path.endsWith('/Contents/Resources/wechat.dylib')
      || module.size < 50 * 1024 * 1024) return;
  try {
    if (Process.arch !== 'arm64') throw new Error('unsupported_arch');
    const addresses = {};
    for (const name of ['startTask', 'buf2resp', 'onTaskEnd', 'wrapperDynamicAuthPredicate']) {
      if (!PROFILE.offsets[name]) throw new Error('missing_profile_entry');
      const address = module.base.add(PROFILE.offsets[name]);
      if (!executable(address)) throw new Error('address_not_executable');
      addresses[name] = address;
    }
    // The other entries are already patched by the first passive script. Only
    // this newly attached helper can be compared against disk's original bytes.
    const expected = PROFILE.expected_bytes.wrapperDynamicAuthPredicate;
    if (typeof expected !== 'string' || expected.length < 16
        || toHex(addresses.wrapperDynamicAuthPredicate.readByteArray(expected.length / 2)) !== expected.toLowerCase())
      throw new Error('auth_predicate_bytes_mismatch');
    function attach(address, hooks) { probe.listeners.push(Interceptor.attach(address, hooks)); }
    attach(addresses.wrapperDynamicAuthPredicate, {
      onEnter: function (args) { this.isText = args[1].toUInt32() === 522; },
      onLeave: function (retval) {
        if (!this.isText) return;
        const value = retval.toInt32() !== 0;
        probe.auth.calls_522++; probe.auth[value ? 'true_results' : 'false_results']++;
        probe.auth.last_result = value;
      }
    });
    attach(addresses.startTask, { onEnter: function (args) {
      try {
        const task = args[0];
        if (!readable(task, 0x218) || task.add(4).readU32() !== 522) return;
        probe.counts.text_starts++;
        if (probe.selected) return;
        probe.selected = { id: task.readU32(), context: task.add(0x58).readPointer() };
        probe.phase = 'text_observed';
        probe.request = requestSummary(task);
      } catch (_) { probe.diagnostic_code = 'request_metadata_unverified'; }
    }});
    attach(addresses.buf2resp, {
      onEnter: function (args) {
        this.selected = !!probe.selected && args[1].toUInt32() === probe.selected.id;
        this.task = null;
        if (!this.selected) return;
        try {
          const slot = this.context.sp.add(0x10);
          if (readable(slot, 8)) this.task = slot.readPointer();
        } catch (_) { /* OnTaskEnd is the independent response-buffer route. */ }
      },
      onLeave: function () {
        if (!this.selected || !this.task) return;
        try {
          if (!readable(this.task, 0x218) || this.task.readU32() !== probe.selected.id) return;
          const result = responseSummary(this.task.add(0x1f0), 'buf2resp_after_native_decode');
          if (result) { probe.response = result; probe.counts.response_observations++; }
        } catch (_) { probe.diagnostic_code = 'response_metadata_unverified'; }
      }
    });
    attach(addresses.onTaskEnd, { onEnter: function (args) {
      if (!probe.selected || args[1].toUInt32() !== probe.selected.id) return;
      probe.counts.matching_ends++;
      probe.completion = { error_type_zero: args[4].toInt32() === 0,
        error_code_zero: args[5].toInt32() === 0,
        user_context_matches: args[2].equals(probe.selected.context) };
      try {
        // Exact-build disassembly shows argument7 is AutoBuffer&, not Task*.
        const result = responseSummary(args[7], 'on_task_end_response_buffer');
        if (result) { probe.response = result; probe.counts.response_observations++; }
      } catch (_) { probe.diagnostic_code = 'completion_metadata_unverified'; }
      probe.phase = 'text_completed';
    }});
    probe.initialized = true; probe.phase = 'waiting_for_one_text';
    send({ type: 'text_probe_loaded', sends_enabled: false });
  } catch (error) {
    for (const listener of probe.listeners) listener.detach();
    probe.listeners = []; probe.phase = 'blocked';
    probe.diagnostic_code = ['unsupported_arch', 'missing_profile_entry', 'address_not_executable',
      'auth_predicate_bytes_mismatch'].indexOf(error.message) !== -1 ? error.message : 'probe_initialization_failed';
  }
}
rpc.exports = { status: status };
const moduleObserver = Process.attachModuleObserver({ onAdded: initialize });
