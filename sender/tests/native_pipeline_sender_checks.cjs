/* Isolated JS workflow checks. No app, Frida, native library or network access. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/wechat_sender/native_pipeline_sender.js'), 'utf8');

class U64 {
  constructor(value) { this.value = BigInt(value); }
  compare(other) { const b = other instanceof U64 ? other.value : BigInt(other); return this.value < b ? -1 : this.value > b ? 1 : 0; }
  toString() { return this.value.toString(); }
}
function fixture(options = {}) {
  const control = {
    now: 100000, identity: 0xfffffffffffffff0n, sessionReady: true, pins: 0,
    libraryLoads: 0, sends: [], jobs: new Map(), nextIndex: 9007199254740993n, throwSend: false,
    released: [], nativeReads: 0, badFingerprint: false, failSmoke: false, rejectSend: false,
  };
  class Pointer {
    constructor(value) { this.value = BigInt(value); }
    add(value) { return new Pointer(this.value + BigInt(value)); }
    isNull() { return this.value === 0n; }
    readByteArray(size) { const bytes = new Uint8Array(size); if (control.badFingerprint) bytes[0] = 1; return bytes.buffer; }
  }
  const base = new Pointer(0x100000000n);
  const native = {
    ws_bridge_version: () => 2,
    ws_abi_selftest: () => new U64(31),
    ws_configure: () => 0,
    ws_bind_executor: () => new Pointer(0x200000000n),
    ws_smoke: (_executor, mode) => {
      const index = control.nextIndex++;
      control.jobs.set(index, { stage: 3, flags: mode === 0 ? 1 : 15, destroyed: 1, error: control.failSmoke ? 1 : 0 });
      return new U64(index);
    },
    ws_smoke_status: index => {
      const state = control.jobs.get(BigInt(index.toString()));
      if (!state) return new U64(0xffffffffffffffffn);
      return new U64(BigInt(state.stage) | BigInt(state.flags) << 8n | BigInt(state.destroyed) << 24n | BigInt(state.error) << 32n);
    },
    ws_send_text: (recipient, text, identity) => {
      control.sends.push({ recipient: recipient.text, text: text.text, identity: identity.toString() });
      if (control.throwSend) throw Error('simulated native dispatch fault');
      if (control.rejectSend) return new U64(0);
      const index = control.nextIndex++;
      control.jobs.set(index, { stage: 1, flags: 0, destroyed: 0, error: 0, fields: [0, 0xffffffff, 0xffffffff] });
      return new U64(index);
    },
    ws_send_field: (index, field) => new U64(control.jobs.get(BigInt(index.toString())).fields[field]),
    ws_release_job: handle => {
      const index = BigInt(handle.toString()), job = control.jobs.get(index);
      if (!job) return 1;
      if (!job.destroyed) return -1;
      control.released.push(index); control.jobs.delete(index); return 0;
    },
    ws_job_metrics: () => {
      const jobs = [...control.jobs.values()];
      return new U64(BigInt(jobs.length) | BigInt(jobs.filter(j => !j.destroyed).length) << 16n |
        BigInt(jobs.filter(j => !j.destroyed && j.error).length) << 32n);
    },
  };
  function NativeFunction(address) {
    if (typeof address === 'string') return native[address];
    if (address.value === base.value + 0x4669774n) return () => new Pointer(control.sessionReady ? 1n : 0n);
    if (address.value === base.value + 0x4670584n) return () => { control.nativeReads++; return new U64(control.identity); };
    throw Error('unexpected native address in mock');
  }
  const profile = { runtime_verified: true, sending_permitted: true, send_framing_verified: true,
    native_pipeline: { enabled: true, functions: { guarded: { offset: '0x100', first16bytes: '00'.repeat(16) } } } };
  if (options.disabled) profile.native_pipeline.enabled = false;
  const sandbox = {
    PROFILE: profile, PIPELINE_LIBRARY_PATH: '/mock/never-loaded.dylib', rpc: {},
    Process: { arch: 'arm64', enumerateModules: () => [{ name: 'wechat.dylib', path: '/mock/WeChat.app/Contents/Resources/wechat.dylib', base }] },
    Module: { load: () => { control.libraryLoads++; return { getExportByName: name => name }; } },
    NativeFunction, Script: { pin: () => { control.pins++; } },
    Memory: { allocUtf8String: text => ({ text }) },
    Date: { now: () => control.now }, setTimeout: callback => { callback(); },
    Uint8Array, Map, BigInt, Number, Error, Promise, encodeURIComponent, unescape,
  };
  vm.runInContext(source, vm.createContext(sandbox));
  const api = sandbox.rpc.exports;
  const complete = (changes = {}) => {
    const index = control.nextIndex - 1n;
    const state = { stage: 3, flags: 127, destroyed: 1, error: 0, fields: [321, 0, 0], ...changes };
    control.jobs.set(index, state);
  };
  return { api, control, complete };
}
const checks = [];
function check(name, run) { checks.push([name, run]); }
async function ready() { const f = fixture(); assert.equal((await f.api.prepare()).ready, true); return f; }
const arm = (f, text='Test', operation='test', sequence=1, recipient='filehelper') => f.api.arm({ recipient, text, operation_id:operation, dispatch_sequence:sequence, ttl_seconds:60 });
const send = (f, text, operation, sequence=1, recipient='filehelper') => {arm(f,text,operation,sequence,recipient);return f.api.sendnative(recipient,text,operation,sequence);};

check('script loading and status do not start native code', () => {
  const f = fixture(); const state = f.api.status();
  assert.equal(state.ready, false); assert.equal(state.can_detach, true);
  assert.equal(f.control.libraryLoads, 0); assert.equal(f.control.sends.length, 0); assert.equal(f.control.nativeReads, 0);
});
check('explicit preparation pins the module and performs only two startup checks', async () => {
  const f = await ready();
  assert.equal(f.control.libraryLoads, 1); assert.equal(f.control.pins, 1);
  assert.equal(f.control.jobs.size, 0); assert.equal(f.control.sends.length, 0);
  assert.equal(f.api.status().can_detach, false);
  await f.api.prepare(); assert.equal(f.control.jobs.size, 0); assert.equal(f.control.pins, 1);
});
check('disabled profiles and mismatched instructions fail before loading the library', async () => {
  for (const kind of ['disabled', 'fingerprint']) {
    const f = fixture({ disabled: kind === 'disabled' }); f.control.badFingerprint = kind === 'fingerprint';
    assert.equal((await f.api.prepare()).ready, false); assert.equal(f.control.libraryLoads, 0);
    assert.equal(f.control.sends.length, 0); assert.throws(() => arm(f), /sender_not_ready/);
  }
});
check('account readiness failure before pinning is retryable without pinning the wrong account', async () => {
  const f = fixture(); f.control.sessionReady = false;
  assert.equal((await f.api.prepare()).ready, false); assert.equal(f.control.pins, 0);
  f.control.sessionReady = true;
  assert.equal((await f.api.prepare()).ready, true); assert.equal(f.control.pins, 1);
});
check('failed native startup checks leave the script pinned and sending blocked', async () => {
  const f = fixture(); f.control.failSmoke = true;
  assert.equal((await f.api.prepare()).ready, false); assert.equal(f.api.status().can_detach, false);
  assert.throws(() => arm(f), /sender_not_ready/); assert.equal(f.control.sends.length, 0);
});
check('exact one-use intent authorizes only the bound message', async () => {
  const f=await ready(); arm(f,'Hello 你好 😀','one');
  for(const args of [['other','Hello 你好 😀','one',1],['filehelper','Changed','one',1],['filehelper','Hello 你好 😀','two',1],['filehelper','Hello 你好 😀','one',2]]) {
    assert.throws(()=>f.api.sendnative(...args),/intent_permit_required/);
  }
  assert.equal(f.api.sendnative('filehelper','Hello 你好 😀','one',1).status,'submitted');
  assert.equal(f.control.sends[0].identity,'18446744073709551600');
  f.complete();assert.equal(f.api.getresult('one').status,'native_pipeline_completed');
  assert.throws(()=>f.api.sendnative('filehelper','Second','two',2),/intent_permit_required/);
});
check('exact duplicate pending, complete and acknowledged operations never resend', async()=>{
  const f=await ready();send(f,'Fixed','same');
  for(const complete of [false,true]){
    if(complete)f.complete();
    assert.equal(f.api.sendnative('filehelper','Fixed','same',1).status,complete?'native_pipeline_completed':'submitted');
  }
  assert.equal(f.api.acknowledge('same',1).acknowledged,true);
  assert.equal(f.api.sendnative('filehelper','Fixed','same',1).status,'native_pipeline_completed');
  assert.equal(f.api.acknowledge('same',1).acknowledged,true);
  for(const args of [['filehelper','Changed','same',1],['other','Fixed','same',1],['filehelper','Fixed','same',2]])assert.throws(()=>f.api.sendnative(...args),/operation_payload_mismatch/);
  assert.equal(f.control.sends.length,1);assert.equal(f.control.released.length,3);
});
check('body completion alone never frees a job or acknowledges its record', async()=>{
  const f=await ready();send(f,'Pending','pending');
  for(const stage of [1,2,4,5,6,3]){
    f.complete({stage,destroyed:0});
    assert.equal(f.api.getresult('pending').completed,false);
    assert.equal(f.api.acknowledge('pending',1).acknowledged,false);
    assert.equal(f.api.status().inflight_count,1);assert.equal(f.control.jobs.size,1);
    assert.throws(()=>f.api.sendnative('filehelper','Other','other',2),/native_not_available/);
  }
  f.complete();const result=f.api.getresult('pending');
  assert.equal(result.completed,true);assert.equal(result.operation_known,true);assert.equal(result.dispatch_sequence,1);
  assert.equal(f.control.jobs.size,0);assert.equal(f.control.released.length,3);
  f.api.getresult('pending');assert.equal(f.control.released.length,3);
});
check('malformed native evidence remains unknown without claiming delivery', async()=>{
  for(const evidence of [{stage:5},{flags:63},{flags:255},{error:1},{fields:[0,0,0]},{fields:[2**32,0,0]},{fields:[321,1,0]},{fields:[321,0,1]},{fields:[0xffffffffffffffffn,0,0]}]){
    const f=await ready();send(f,'Test','bad');f.complete(evidence);
    const result=f.api.getresult('bad');assert.equal(result.status,'outcome_unknown');assert.equal(result.completed,true);
    assert.equal(result.operation_known,true);assert.equal(result.dispatch_sequence,1);assert.equal(result.local_id,undefined);
    assert.equal(f.control.jobs.size,0);assert.equal(f.api.acknowledge('bad',1).acknowledged,true);
  }
});
check('native completion reports local correlation without claiming server delivery',async()=>{
  const f=await ready();send(f,'Test','good');f.complete();const result=f.api.getresult('good');
  assert.equal(result.status,'native_pipeline_completed');assert.equal(result.local_id,321);
  assert.equal(result.server_id,undefined);assert.equal(result.delivery_confirmed,undefined);assert.equal(f.api.status().can_detach,false);
});
check('account changes block new sends',async()=>{
  const f=await ready();arm(f);f.control.identity++;
  assert.equal(f.api.status().ready,false);assert.throws(()=>arm(f),/sender_not_ready/);
  assert.throws(()=>f.api.sendnative('filehelper','Test','test',1),/native_not_available/);
  assert.equal(f.control.sends.length,0);assert.equal(JSON.stringify(f.api.status()).includes(f.control.identity.toString()),false);
});
check('expired permits and malformed UTF8 never dispatch',async()=>{
  const f=await ready();arm(f);f.control.now+=60001;
  assert.throws(()=>f.api.sendnative('filehelper','Test','test',1),/intent_permit_required/);
  for(const text of ['a\0b','\ud800','😀'.repeat(1025),''])assert.throws(()=>arm(f,text),/invalid_text/);
  for(const sequence of [0,-1,1.5,2**53,NaN])assert.throws(()=>arm(f,'Test','test',sequence),/invalid_dispatch_sequence/);
  assert.equal(f.control.sends.length,0);
});
check('native pre-enqueue rejection is terminal and consumes its sequence',async()=>{
  const f=await ready();f.control.rejectSend=true;const result=send(f,'Test','reject');
  assert.equal(result.status,'rejected');assert.equal(result.completed,true);assert.equal(result.dispatch_sequence,1);
  assert.equal(f.api.sendnative('filehelper','Test','reject',1).status,'rejected');
  assert.equal(f.api.acknowledge('reject',1).acknowledged,true);assert.equal(f.control.sends.length,1);assert.equal(f.control.jobs.size,0);
});
check('bridge dispatch exceptions never retry and block further dispatch',async()=>{
  const f=await ready();f.control.throwSend=true;const result=send(f,'Test','fault');
  assert.equal(result.status,'outcome_unknown');assert.equal(result.completed,true);
  assert.equal(f.api.sendnative('filehelper','Test','fault',1).status,'outcome_unknown');
  assert.equal(f.control.sends.length,1);assert.equal(f.api.status().ready,false);assert.throws(()=>arm(f),/sender_not_ready/);
});
check('uncertain enqueue retains native ownership until eventual destruction',async()=>{
  const f=await ready();send(f,'Test','late');f.complete({stage:1,destroyed:0,error:7});
  const result=f.api.getresult('late');assert.equal(result.status,'outcome_unknown');assert.equal(result.completed,false);
  assert.equal(f.api.status().deferred_cleanup_count,1);assert.equal(f.api.acknowledge('late',1).acknowledged,false);
  assert.equal(f.control.jobs.size,1);assert.equal(f.control.released.length,2);
  f.complete({error:7});assert.equal(f.api.getresult('late').completed,true);
  assert.equal(f.control.jobs.size,0);assert.equal(f.api.acknowledge('late',1).acknowledged,true);
});
check('1024 sequential sends use bounded state and reject forgotten sequences',async()=>{
  const f=await ready();
  for(let sequence=1;sequence<=1024;sequence++){
    send(f,'Test','operation-'+sequence,sequence);f.complete();
    assert.equal(f.api.getresult('operation-'+sequence).completed,true);
    assert.equal(f.api.acknowledge('operation-'+sequence,sequence).acknowledged,true);
    assert.equal(f.control.jobs.size,0);assert.equal(f.api.status().unacknowledged_count,0);
    assert.ok(f.api.status().recent_result_count<=64);
  }
  assert.equal(f.control.sends.length,1024);assert.equal(f.control.released.length,1026);
  assert.equal(f.api.status().operation_lifetime_limit,null);assert.equal(f.api.status().operation_capacity_remaining,64);
  assert.equal(f.api.getresult('operation-1').operation_known,false);
  assert.throws(()=>f.api.sendnative('filehelper','Test','operation-1',1),/dispatch_sequence_already_consumed/);
  assert.equal(f.api.acknowledge('operation-1',1).acknowledged,true);
  assert.equal(f.control.sends.length,1024);
});
check('unacknowledged completions apply temporary backpressure, acknowledgement recovers',async()=>{
  const f=await ready();
  for(let sequence=1;sequence<=64;sequence++){send(f,'Test','op'+sequence,sequence);f.complete();f.api.getresult('op'+sequence);}
  assert.equal(f.api.status().operation_capacity_remaining,0);assert.equal(f.api.status().sends_enabled,false);
  assert.throws(()=>send(f,'Test','op65',65),/native_not_available/);
  assert.throws(()=>f.api.acknowledge('op1',2),/operation_sequence_mismatch/);
  assert.equal(f.api.acknowledge('op1',1).acknowledged,true);
  assert.equal(send(f,'Test','op65',65).status,'submitted');assert.equal(f.control.sends.length,65);
});
check('unknown lookup is never rejection evidence and does not allocate native state',async()=>{
  const f=await ready();const result=f.api.getresult('missing');
  assert.equal(result.status,'outcome_unknown');assert.equal(result.operation_known,false);assert.equal(result.completed,false);
  assert.equal(result.dispatch_sequence,undefined);assert.equal(f.control.jobs.size,0);assert.equal(f.control.sends.length,0);
});
check('missing native handles block safely without manufacturing completion',async()=>{
  const f=await ready();send(f,'Test','missing');f.control.jobs.clear();
  assert.equal(f.api.getresult('missing').completed,false);assert.equal(f.api.status().ready,false);
  assert.equal(f.api.acknowledge('missing',1).acknowledged,false);
});

(async () => {
  let failed = 0;
  for (const [name, run] of checks) {
    try { await run(); }
    catch (error) { failed++; console.error(`FAIL ${name}: ${error.message}`); }
  }
  console.log(`${checks.length - failed}/${checks.length} native pipeline JS checks passed; all native APIs mocked.`);
  if (failed) process.exitCode = 1;
})();
