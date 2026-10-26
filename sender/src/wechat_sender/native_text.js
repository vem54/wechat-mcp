/* SPDX-License-Identifier: GPL-3.0-only
 * Exact-build, passive native transport probe.
 * Interoperability research derives from yincongcyincong/wechat_chatter,
 * copyright2026 yincongcyincong and contributors. See THIRD_PARTY_NOTICES.md.
 *
 * No native task is constructed or started here. Normal traffic is never
 * replaced or modified. In particular, this file does not transplant a
 * std::map root, copy C++ task storage or bypass app-specific wire framing.
 * PROFILE is injected by a host that verifies the complete code-section hash.
 */
'use strict';

const names = ['taskCtor', 'taskDtor', 'startTask', 'req2buf', 'buf2resp',
  'onTaskEnd', 'autoBufferWrite', 'stringAssign'];
const state = {
  phase: 'waiting_module', diagnostic_code: 'app_request_framing_unverified',
  probe_counts: { start: 0, request: 0, request_return: 0, request_true: 0,
    response: 0, end: 0, valid_request_buffer: 0, valid_response_buffer: 0 },
  listeners: [], initialized: false, static_match: false,
  natural: new Map(), correlated_requests: 0, correlated_responses: 0,
  callback_offsets: {}, abi_observed: false,
  prepared_task_counts: { start_flag_0: 0, start_flag_1: 0,
    request_flag_0: 0, request_flag_1: 0, request_id_matches: 0,
    response_flag_0: 0, response_flag_1: 0, response_id_matches: 0,
    end_flag_0: 0, end_flag_1: 0, end_id_matches: 0,
    prepared_buffer_valid: 0, prepared_buffer_nonempty: 0,
    response_buffer_valid: 0, response_buffer_nonempty: 0 }
};

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
}
function readable(address, count) {
  if (!address || address.isNull() || count < 0) return false;
  const range = Process.findRangeByAddress(address);
  return range !== null && range.protection.indexOf('r') >= 0
    && address.add(count).compare(range.base.add(range.size)) <= 0;
}
function executable(address) {
  const range = address && !address.isNull() ? Process.findRangeByAddress(address) : null;
  return range !== null && range.protection.indexOf('x') >= 0;
}
function validBuffer(address) {
  if (!readable(address, 40)) return false;
  const data = address.readPointer();
  const position = address.add(8).readU64().toNumber();
  const length = address.add(16).readU64().toNumber();
  const capacity = address.add(24).readU64().toNumber();
  return Number.isSafeInteger(length) && Number.isSafeInteger(position)
    && Number.isSafeInteger(capacity) && position >= 0 && position <= length
    && length <= capacity && capacity <= 64 * 1024 * 1024
    && (length === 0 || readable(data, length));
}
function fail(code) {
  state.phase = 'blocked'; state.diagnostic_code = code;
  send({ type: 'blocked', reason: code });
}
function status() {
  return { phase: state.phase, ready: false, armed: false,
    probe_counts: Object.assign({}, state.probe_counts),
    diagnostic_code: state.diagnostic_code,
    static_addresses_match: state.static_match,
    correlated_requests: state.correlated_requests,
    correlated_responses: state.correlated_responses,
    callback_offsets: Object.assign({}, state.callback_offsets),
    prepared_task_counts: Object.assign({}, state.prepared_task_counts),
    transport_abi_observed: state.abi_observed,
    request_framing_validated: false, send_implemented: false };
}
function initialize(module) {
  if (state.initialized || state.phase === 'blocked' || module.name !== 'wechat.dylib'
      || !module.path.endsWith('/Contents/Resources/wechat.dylib')
      || module.size < 50 * 1024 * 1024) return;
  try {
    if (Process.arch !== 'arm64' || Process.pointerSize !== 8) throw new Error('unsupported_arch');
    const addresses = {};
    for (const name of names) {
      const offset = PROFILE.offsets[name], expected = PROFILE.expected_bytes[name];
      if (!offset || typeof expected !== 'string' || expected.length < 16 || expected.length % 2)
        throw new Error('incomplete_profile');
      const address = module.base.add(offset);
      if (!executable(address) || hex(address.readByteArray(expected.length / 2)) !== expected.toLowerCase())
        throw new Error('profile_bytes_mismatch');
      addresses[name] = address;
    }
    state.static_match = true;
    function attach(address, callbacks) {
      state.listeners.push(Interceptor.attach(address, callbacks));
    }
    function discoverCallback(manager, role, slot) {
      if (state.callback_offsets[role] || !readable(manager.add(0x10), 8)) return;
      const callback = manager.add(0x10).readPointer();
      if (!readable(callback, 8)) return;
      const vtable = callback.readPointer();
      if (!readable(vtable.add(slot), 8)) return;
      const target = vtable.add(slot).readPointer();
      if (!executable(target) || target.compare(module.base) < 0
          || target.compare(module.base.add(module.size)) >= 0) return;
      // Only a public-code relative offset leaves the process, never an object
      // pointer, payload, account identifier, recipient, key or message body.
      state.callback_offsets[role] = target.sub(module.base).toString();
      send({ type: 'probe_callback', role: role, relative_offset: state.callback_offsets[role] });
    }
    function observePreparedTask(task, stage, id) {
      if (!readable(task, 0x218)) return;
      if (stage !== 'start') {
        if (task.readU32() !== id) return;
        state.prepared_task_counts[stage + '_id_matches']++;
      }
      const flag = task.add(0x1c0).readU8();
      if (flag === 0 || flag === 1) state.prepared_task_counts[stage + '_flag_' + flag]++;
      if (flag === 1 && validBuffer(task.add(0x1c8))) {
        state.prepared_task_counts.prepared_buffer_valid++;
        if (task.add(0x1d8).readU64().compare(0) > 0)
          state.prepared_task_counts.prepared_buffer_nonempty++;
      }
      if (stage === 'end' && flag === 1 && validBuffer(task.add(0x1f0))) {
        state.prepared_task_counts.response_buffer_valid++;
        if (task.add(0x200).readU64().compare(0) > 0)
          state.prepared_task_counts.response_buffer_nonempty++;
      }
    }
    attach(addresses.startTask, { onEnter: function (args) {
      state.probe_counts.start++;
      try {
        const task = args[0];
        if (!readable(task, 0x218)) return;
        const id = task.readU32(), command = task.add(4).readU32();
        if (!id || command > 65535) return;
        observePreparedTask(task, 'start', id);
        state.natural.set(id, { request: false, response: false });
        if (state.natural.size > 256) state.natural.delete(state.natural.keys().next().value);
      } catch (_) { fail('task_entry_shape_unverified'); }
    }});
    attach(addresses.req2buf, {
      onEnter: function (args) {
        state.probe_counts.request++;
        this.task = args[1].toUInt32(); this.buffer = args[4];
        try {
          // The semantically matched MMReq2Buf wrapper has a third stack
          // argument: const Task*. Observe its metadata without its payload.
          const slot = this.context.sp.add(0x10);
          if (readable(slot, 8)) observePreparedTask(slot.readPointer(), 'request', this.task);
        } catch (_) { /* Optional metadata cannot alter or block normal traffic. */ }
        try { discoverCallback(args[0], 'req2buf', 0x50); }
        catch (_) { /* A missing optional callback observation cannot alter traffic. */ }
      },
      onLeave: function (retval) {
        state.probe_counts.request_return++;
        if (retval.toInt32() === 1) state.probe_counts.request_true++;
        try {
          if (validBuffer(this.buffer)) {
            state.probe_counts.valid_request_buffer++;
            const entry = state.natural.get(this.task);
            if (entry && retval.toInt32() === 1) {
              entry.request = true; state.correlated_requests++;
            }
          }
        } catch (_) { fail('request_buffer_shape_unverified'); }
      }
    });
    attach(addresses.buf2resp, { onEnter: function (args) {
      state.probe_counts.response++;
      try {
        const task = args[1].toUInt32(), entry = state.natural.get(task);
        const slot = this.context.sp.add(0x10);
        if (readable(slot, 8)) observePreparedTask(slot.readPointer(), 'response', task);
        if (validBuffer(args[4])) {
          state.probe_counts.valid_response_buffer++;
          if (entry && entry.request) { entry.response = true; state.correlated_responses++; }
        }
        discoverCallback(args[0], 'buf2resp', 0x58);
      } catch (_) { fail('response_buffer_shape_unverified'); }
    }});
    attach(addresses.onTaskEnd, { onEnter: function (args) {
      state.probe_counts.end++;
      const id = args[1].toUInt32(), entry = state.natural.get(id);
      try { observePreparedTask(args[7], 'end', id); }
      catch (_) { /* Metadata inspection must not affect task completion. */ }
      if (entry && entry.request && entry.response) state.abi_observed = true;
      state.natural.delete(id);
    }});
    state.initialized = true; state.phase = 'passive_probe';
    send({ type: 'probe_loaded', static_addresses_match: true, send_enabled: false });
  } catch (error) {
    for (const listener of state.listeners) listener.detach();
    state.listeners = []; fail(error.message || 'probe_initialization_failed');
  }
}

rpc.exports = {
  status: status,
  arm: function () { throw new Error('app_request_framing_unverified'); },
  disarm: status,
  sendtext: function () { throw new Error('app_request_framing_unverified'); }
};
const moduleObserver = Process.attachModuleObserver({ onAdded: initialize });
