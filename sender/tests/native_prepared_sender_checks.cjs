/* Pure JavaScript checks only: no Frida process, app, native code or network. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../src/wechat_sender/native_prepared_sender.js'), 'utf8');
const allocations = [];
let nextAddress = 0x10000000n;
let replacements = 0, pins = 0;
const instructions = [], callbacks = new Map();
class U64 {
  constructor(n) { this.value = BigInt(n); }
  compare(other) { const b = BigInt(other instanceof U64 ? other.value : other); return this.value < b ? -1 : this.value > b ? 1 : 0; }
  toNumber() { return Number(this.value); }
  toString() { return this.value.toString(); }
}
class Pointer {
  constructor(n) { this.value = BigInt(n instanceof Pointer ? n.value : n); }
  add(n) { return new Pointer(this.value + BigInt(n)); }
  equals(p) { return this.value === p.value; }
  isNull() { return this.value === 0n; }
  compare(p) { return this.value < p.value ? -1 : this.value > p.value ? 1 : 0; }
  storage(size) {
    const a = allocations.find(a => this.value >= a.base.value && this.value + BigInt(size) <= a.base.value + BigInt(a.bytes.length));
    if (!a) throw Error('mock_memory_bounds');
    return { a, offset: Number(this.value - a.base.value) };
  }
  readU64() { const {a, offset} = this.storage(8); return new U64(new DataView(a.bytes.buffer).getBigUint64(offset, true)); }
  writeU64(n) { const {a, offset} = this.storage(8); new DataView(a.bytes.buffer).setBigUint64(offset, BigInt(n), true); }
  readU32() { const {a, offset} = this.storage(4); return new DataView(a.bytes.buffer).getUint32(offset, true); }
  writeU32(n) { const {a, offset} = this.storage(4); new DataView(a.bytes.buffer).setUint32(offset, n, true); }
  readPointer() { return new Pointer(this.readU64().value); }
  writePointer(p) { this.writeU64(p.value); }
  writeByteArray(bytes) { const {a, offset} = this.storage(bytes.length); a.bytes.set(bytes, offset); }
  readByteArray(size) { const {a, offset} = this.storage(size); return a.bytes.slice(offset, offset + size).buffer; }
}
function allocate(size) {
  const base = new Pointer(nextAddress); nextAddress += BigInt(size + 4096);
  allocations.push({base, bytes: new Uint8Array(size), protection:'rw-'}); return base;
}
const memory = {
  alloc: allocate,
  patchCode: (address, size, callback) => callback(address),
  queryProtection: address => address.storage(1).a.protection,
  protect: (address, size, protection) => { address.storage(size).a.protection = protection; return true; }
};
class Writer {
  putLdrRegAddress(...args) { instructions.push(['address', ...args]); }
  putLdrRegRegOffset(...args) { instructions.push(['load', ...args]); }
  putCbzRegLabel(...args) { instructions.push(['cbz', ...args]); }
  putCmpRegReg(...args) { instructions.push(['cmp', ...args]); }
  putBCondLabel(...args) { instructions.push(['conditional', ...args]); }
  putLabel(...args) { instructions.push(['label', ...args]); }
  putBrReg(...args) { instructions.push(['branch', ...args]); }
  flush() {}
  dispose() {}
}
function NativeCallback(fn) { const pointer = allocate(8); callbacks.set(pointer.value, fn); return pointer; }
const profile = { sending_permitted:false, send_framing_verified:false };
const sandbox = {
  PROFILE: profile, rpc: {}, Uint8Array, Date, Map, BigInt, Number, Error,
  Process: { pageSize:4096, findRangeByAddress(address) {
    try { const {a} = address.storage(1); return {base:a.base,size:a.bytes.length,protection:a.protection}; }
    catch (_) { return null; }
  } },
  Memory: memory, NativeCallback, Arm64Writer:Writer,
  Script: { pin() { pins++; } }, ptr: n => new Pointer(n),
  Interceptor: { replaceFast() { replacements++; return new Pointer(0x77770000n); }, flush() {} },
  send() {}
};
const context = vm.createContext(sandbox);
vm.runInContext(source, context);
const run = text => vm.runInContext(text, context);
sandbox.expectedRequest = {client_id:0x12345678n,timestamp:BigInt(Math.floor(Date.now()/1000)),
  recipient:new Uint8Array(Buffer.from('filehelper'))};
let checks = 0;
function check(name, body) { body(); checks++; }
function vi(value) {
  let n = BigInt(value); const output = [];
  while (n >= 128n) { output.push(Number(n & 127n) | 128); n >>= 7n; }
  return output.concat(Number(n));
}
const integer = (n, v) => [...vi(n << 3), ...vi(v)];
const blob = (n, b) => [...vi((n << 3) | 2), ...vi(b.length), ...b];
const enc = s => Array.from(Buffer.from(s));
function rawText(recipient='filehelper', options={}) {
  const body = [...blob(1, blob(1,enc(recipient))), ...blob(2,options.content || enc('non-sensitive test')),
    ...integer(3,1), ...integer(4,options.timestamp || Math.floor(Date.now()/1000)),
    ...integer(5,options.clientId === undefined ? 0x12345678n : options.clientId),
    ...blob(6,enc('<msgsource><alnode><fr>1</fr></alnode></msgsource>'))];
  return new Uint8Array([...integer(1,1), ...blob(2,body)]);
}
function nativeBuffer(bytes) {
  const object = allocate(40), data = allocate(Math.max(1, bytes.length)); data.writeByteArray(bytes);
  object.writePointer(data); object.add(8).writeU64(bytes.length);
  object.add(16).writeU64(bytes.length); object.add(24).writeU64(bytes.length); return object;
}
check('loading/status has no mutations', () => {
  assert.equal(replacements,0); assert.equal(pins,0); assert.equal(allocations.length,0);
  assert.equal(sandbox.rpc.exports.status().ready,false);
  assert.equal(sandbox.rpc.exports.status().can_detach,true);
  assert.equal(sandbox.rpc.exports.arm({recipient:'filehelper'}).armed,false);
  assert.equal(sandbox.rpc.exports.sendtext(0,'00','operation_1').status,'rejected');
  assert.equal(allocations.length,0);
});
check('Frida-cloaked allocations use exact owned bounds and page protection', () => {
  const oldFind = sandbox.Process.findRangeByAddress;
  sandbox.Process.findRangeByAddress = () => null;
  const task = run('allocateTask()'); sandbox.task = task;
  assert.equal(run('readable(task.add(496), 40)'),true);
  assert.equal(run('readable(task.add(496), 41)'),false);
  run('releaseTaskRange(task)');
  assert.equal(run('readable(task.add(496), 40)'),true);
  task.storage(1).a.protection = '---';
  assert.equal(run('readable(task.add(496), 40)'),false);
  sandbox.Process.findRangeByAddress = oldFind;
});
check('prepared account identity is private and rejects later account switches', () => {
  sandbox.accountSession=allocate(8); sandbox.accountIdentity=new U64(12345678901234567890n);
  sandbox.getAccountIdentity=()=>sandbox.accountIdentity;
  run('sender.native = {wrapperAppSessionGetter:()=>accountSession, wrapperEnvelopeIdentityGetter:()=>getAccountIdentity(), wrapperDynamicAuthPredicate:()=>false}');
  assert.equal(run('sender.account_identity'),null);
  run('account()'); // Readiness checks alone must not pin a failed preparation.
  assert.equal(run('sender.account_identity'),null);
  run('sender.account_identity = account().identity');
  run('account()');
  sandbox.accountIdentity=new U64(12345678901234567891n);
  assert.throws(()=>run('account()'),/prepared_account_changed/);
  assert.equal(JSON.stringify(sandbox.rpc.exports.status()).includes('12345678901234567890'),false);
  run('sender.account_identity = null; sender.native = null');
});
check('current text schema accepts recipient and Unicode', () => {
  sandbox.input = rawText('filehelper',{content:enc('Hi 你好 😀')});
  run('validateText(input, "filehelper")');
});
check('recipient must match one-use authorization', () => {
  sandbox.input = rawText('different'); assert.throws(() => run('validateText(input, "filehelper")'), /recipient_mismatch/);
});
check('stale text is rejected', () => {
  sandbox.input = rawText('filehelper',{timestamp:1}); assert.throws(() => run('validateText(input, "filehelper")'), /stale_text_timestamp/);
});
check('current uint32 client ID boundaries accepted; zero/old35bit rejected', () => {
  for (const clientId of [1n, 0xffffffffn]) {
    sandbox.input = rawText('filehelper',{clientId}); run('validateText(input, "filehelper")');
  }
  for (const clientId of [0n, 0x100000000n, 1n << 34n, (1n << 35n) - 1n]) {
    sandbox.input = rawText('filehelper',{clientId});
    assert.throws(() => run('validateText(input, "filehelper")'), /invalid_client_id/);
  }
});
check('UTF-8 overlong, surrogates, NUL and oversized text rejected', () => {
  for (const content of [[0xc0,0x80],[0xed,0xa0,0x80],[0],Array(4097).fill(65)]) {
    sandbox.input = rawText('filehelper',{content}); assert.throws(() => run('validateText(input, "filehelper")'), /invalid_text_content/);
  }
});
check('duplicate/unknown request fields rejected', () => {
  sandbox.input = new Uint8Array([...rawText(), ...integer(1,1)]);
  assert.throws(() => run('validateText(input, "filehelper")'), /invalid_text_schema/);
});
check('uint64 envelope preserves precision up to maximum', () => {
  sandbox.input = rawText(); sandbox.identity = new U64(0xffffffffffffffffn);
  assert.equal(run('one(protobuf(envelope(input, identity)), 1, 0).value'),0xffffffffffffffffn);
});
check('overflow and truncated protobuf rejected', () => {
  sandbox.input = new Uint8Array([8,...Array(10).fill(255)]);
  assert.throws(() => run('protobuf(input)'),/protobuf_overflow/);
  sandbox.input = new Uint8Array([18,10,1]); assert.throws(() => run('protobuf(input)'),/protobuf_field_bounds/);
});
check('explicit server ret zero is response evidence, not message ack', () => {
  sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522), ...blob(2,blob(1,integer(1,0)))]));
  const evidence = run('responseEvidence(response)');
  assert.equal(evidence.server_ret_present,true); assert.equal(evidence.server_ret,0);
  assert.equal(evidence.message_ret_present,false);
});
check('per-item response correlated to exact client ID, recipient and timestamp', () => {
  const item = [...integer(1,0), ...blob(2,blob(1,enc('filehelper'))), ...integer(4,0x12345678),
    ...integer(5,sandbox.expectedRequest.timestamp), ...integer(8,0xffffffffffffffffn)];
  const cgi = [...blob(1,integer(1,0)),...blob(3,item)];
  sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522), ...blob(2,cgi)]));
  const evidence = run('responseEvidence(response, expectedRequest)');
  assert.equal(evidence.message_ret_present,true); assert.equal(evidence.message_ret,0);
  assert.equal(evidence.server_id_present,true); assert.equal(evidence.server_id_nonzero,true);
  assert.equal(evidence.server_id,'18446744073709551615');
  assert.equal(evidence.response_field4_matches_request_client_id,true);
  assert.equal(evidence.client_id_correlation_verified,true);
  assert.equal(evidence.response_recipient_matches,true); assert.equal(evidence.response_timestamp_matches,true);
  assert.equal(evidence.message_correlated,true);
});
check('wrong, missing or duplicate correlation fields cannot acknowledge', () => {
  const id=integer(4,0x12345678), recipient=blob(2,blob(1,enc('filehelper'))),
    timestamp=integer(5,sandbox.expectedRequest.timestamp);
  const cases=[
    [...integer(4,0x12345679),...recipient,...timestamp],
    [...integer(4,0x112345678n),...recipient,...timestamp],
    [...id,...blob(2,blob(1,enc('another_recipient'))),...timestamp],
    [...id,...recipient,...integer(5,sandbox.expectedRequest.timestamp+1n)],
    [...recipient,...timestamp], [...id,...timestamp], [...id,...recipient],
    [...id,...id,...recipient,...timestamp], [...id,...recipient,...recipient,...timestamp],
    [...id,...recipient,...timestamp,...timestamp],
    [...id,...blob(2,[...blob(1,enc('filehelper')),...blob(1,enc('filehelper'))]),...timestamp]
  ];
  for (const correlation of cases) {
    const cgi=[...blob(1,integer(1,0)),...blob(3,[...integer(1,0),...correlation,...integer(8,1)])];
    sandbox.response=nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,cgi)]));
    assert.equal(run('responseEvidence(response, expectedRequest).message_correlated'),false);
  }
});
check('oversized nonzero result codes cannot wrap into success', () => {
  const cgi=[...blob(1,integer(1,0x100000000n)),...blob(3,[...integer(1,0x100000000n),...integer(8,1)])];
  sandbox.response=nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,cgi),...integer(5,0x100000000n)]));
  const evidence=run('responseEvidence(response, expectedRequest)');
  assert.equal(evidence.server_ret_zero,false); assert.equal(evidence.message_ret_zero,false);
  assert.equal(evidence.native_decode_error_zero,false);
});
check('only fully correlated clean native completion becomes acknowledged', () => {
  const item=[...integer(1,0),...blob(2,blob(1,enc('filehelper'))),...integer(4,0x12345678),
    ...integer(5,sandbox.expectedRequest.timestamp),...integer(8,123456789012345n)];
  const cgi=[...blob(1,integer(1,0)),...blob(3,item)];
  sandbox.response=nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,cgi)]));
  sandbox.ownedContext=allocate(8);
  for (const nativeError of [0,1]) {
    sandbox.nativeError=nativeError;
    run('sender.active = {context:ownedContext,sent_metadata:expectedRequest,completed:false,result:{task_id:789,operation_id:"check_op_1"}}; sender.byTask.set(789,sender.active)');
    run('complete(ptr(0),789,ownedContext,ptr(0),nativeError,0,ptr(0),response)');
    assert.equal(run('sender.byTask.get(789).result.status'),nativeError?'outcome_unknown':'acknowledged');
  }
});
check('missing per-message fields and ambiguous item count fail closed', () => {
  const base = blob(1,integer(1,0));
  const cases = [base, [...base,...blob(3,integer(8,1))], [...base,...blob(3,integer(1,0))],
    [...base,...blob(3,[...integer(1,0),...integer(8,0)])],
    [...base,...blob(3,[...integer(1,0),...integer(8,1)]),...blob(3,[...integer(1,0),...integer(8,2)])]];
  for (const cgi of cases) {
    sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,cgi)]));
    const evidence = run('responseEvidence(response, expectedRequest)');
    assert.equal(evidence.message_ret_present && evidence.message_ret === 0
      && evidence.server_id_present && evidence.server_id_nonzero,false);
  }
  sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,[...base,
    ...blob(3,[...integer(1,0xffffffffffffffffn),...integer(8,1)])])]));
  assert.equal(run('responseEvidence(response).message_ret'),-1);
});
check('absent BaseResponse/ret cannot become success', () => {
  for (const body of [[],blob(1,[])]) {
    sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,body)]));
    assert.throws(() => run('responseEvidence(response)'),/protobuf_schema/);
  }
});
check('signed ret and command correlation checked', () => {
  sandbox.response = nativeBuffer(new Uint8Array([...integer(1,522),...blob(2,blob(1,integer(1,0xffffffffffffffffn)))]));
  assert.equal(run('responseEvidence(response).server_ret'),-1);
  sandbox.response = nativeBuffer(new Uint8Array([...integer(1,123),...blob(2,blob(1,integer(1,0)))]));
  assert.throws(() => run('responseEvidence(response)'),/response_command_mismatch/);
});
check('dispatcher installs only after explicit prepare path; pinned forever', () => {
  run('sender.addresses = {wrapperAppOnTaskEnd: ptr(0x44440000)}; installDispatcher()');
  assert.equal(replacements,1); assert.equal(pins,1);
  assert.equal(sandbox.rpc.exports.status().can_detach,false);
  assert.equal(sandbox.rpc.exports.status().lifetime_policy,'pinned_until_app_exit');
});
function simulate(taskId, userContext) {
  const regs = Object.fromEntries(Array.from({length:31},(_,i)=>['x'+i,BigInt(0x1000+i)]));
  regs.x1 = BigInt(taskId); regs.x2 = BigInt(userContext); regs.sp = 0xaaaabbbbccccddddn;
  const before = {...regs}, labels = new Map(); let same = false;
  instructions.forEach((op,i)=>{if(op[0]==='label')labels.set(op[1],i);});
  const get = r => r[0] === 'w' ? regs['x'+r.slice(1)] & 0xffffffffn : regs[r];
  const set = (r,v) => { regs[r[0]==='w'?'x'+r.slice(1):r] = r[0]==='w'?v & 0xffffffffn:v; };
  for (let i=0;i<instructions.length;i++) {
    const [op,a,b,c] = instructions[i];
    if (op==='address')set(a,b.value);
    else if(op==='load') { const p = new Pointer(get(b)+BigInt(c)); set(a,a[0]==='w'?BigInt(p.readU32()):p.readU64().value); }
    else if(op==='cbz') { if(get(a)===0n)i=labels.get(b); }
    else if(op==='cmp')same=get(a)===get(b);
    else if(op==='conditional') { assert.equal(a,'ne'); if(!same)i=labels.get(b); }
    else if(op==='branch') {
      for(const register of Object.keys(before)) if(!['x16','x17'].includes(register))assert.equal(regs[register],before[register]);
      return get(a);
    }
  }
  throw Error('no_branch');
}
check('normal task preserves registers and forwards exact trampoline', () => {
  assert.equal(simulate(123,0xabcdefn),0x77770000n);
});
check('own task requires exact 32-bit ID AND full 64-bit token', () => {
  const slot = run('sender.dispatch.slots.add(16 * 7)');
  slot.add(8).writePointer(new Pointer(0x1000000000000001n)); slot.writeU32(123);
  const target = run('sender.dispatch.callback.value');
  assert.equal(simulate(123,0x1000000000000001n),target);
  assert.equal(simulate(123,0x2000000000000001n),0x77770000n);
  assert.equal(simulate(124,0x1000000000000001n),0x77770000n);
  assert.equal(simulate(0,0n),0x77770000n);
});
console.log(`Passed ${checks} pure sender checks; no native code or app accessed.`);
