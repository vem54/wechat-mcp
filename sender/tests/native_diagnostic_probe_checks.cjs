/* In-memory diagnostic privacy/schema checks; no Frida or app access. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const heap = []; let next = 0x100000n;
class Word {
  constructor(value) { this.value = BigInt(value); }
  toString() { return this.value.toString(); }
  toNumber() { return Number(this.value); }
  compare(other) { const b = BigInt(other instanceof Word ? other.value : other); return this.value < b ? -1 : this.value > b ? 1 : 0; }
}
class Pointer {
  constructor(value) { this.value = BigInt(value); }
  add(value) { return new Pointer(this.value + BigInt(value)); }
  sub(other) { return new Pointer(this.value - other.value); }
  isNull() { return this.value === 0n; }
  equals(other) { return this.value === other.value; }
  compare(other) { return this.value < other.value ? -1 : this.value > other.value ? 1 : 0; }
  toString() { return '0x' + this.value.toString(16); }
  view(size) {
    const entry = heap.find(e => this.value >= e.base.value && this.value + BigInt(size) <= e.base.value + BigInt(e.bytes.length));
    if (!entry) throw Error('outside_mock');
    return new DataView(entry.bytes.buffer, Number(this.value - entry.base.value), size);
  }
  readU8() { return this.view(1).getUint8(0); }
  readU32() { return this.view(4).getUint32(0,true); }
  readS32() { return this.view(4).getInt32(0,true); }
  readU64() { return new Word(this.view(8).getBigUint64(0,true)); }
  readPointer() { return new Pointer(this.readU64().value); }
  writeU8(v) { this.view(1).setUint8(0,v); }
  writeU32(v) { this.view(4).setUint32(0,v,true); }
  writeU64(v) { this.view(8).setBigUint64(0,BigInt(v),true); }
  writePointer(p) { this.writeU64(p.value); }
}
function allocate(size, contents=[]) {
  const base = new Pointer(next); next += BigInt(size + 1024);
  const bytes = new Uint8Array(size); bytes.set(contents); heap.push({base,bytes}); return base;
}
function bufferAt(address, bytes) {
  const data = allocate(bytes.length,bytes); address.writePointer(data);
  for (const offset of [8,16,24]) address.add(offset).writeU64(bytes.length);
}
function vi(value) {
  let n=BigInt(value); const out=[];
  while(n>=128n){out.push(Number(n & 127n)|128);n>>=7n;}return [...out,Number(n)];
}
const integer=(number,value)=>[...vi(number<<3),...vi(value)];
const blob=(number,bytes)=>[...vi(number<<3|2),...vi(bytes.length),...bytes];
const utf8=value=>Array.from(Buffer.from(value));
const marker='MCP diagnostic exact marker';
const clientId=3456789012n, timestamp=BigInt(Math.floor(Date.now()/1000));
function makeTask(text=marker,to='filehelper') {
  const body=[...blob(1,blob(1,utf8(to))),...blob(2,utf8(text)),...integer(3,1),
    ...integer(4,timestamp),...integer(5,clientId),...blob(6,utf8('<msgsource><alnode><fr>1</fr></alnode></msgsource>'))];
  const raw=[...integer(1,1),...blob(2,body)];
  const envelope=[...integer(1,12345678901234567890n),...blob(2,raw),...integer(3,0),...integer(4,0),
    ...blob(7,utf8('PRIVATE_AUTH_KEY_NEVER_OUTPUT'))];
  const task=allocate(0x218);task.writeU32(123);task.add(4).writeU32(522);task.add(0x10).writeU32(1);
  task.add(0x31).writeU8(1);task.add(0x1c0).writeU8(1);task.add(0x60).writeU64(522);
  const cgi=utf8('/cgi-bin/micromsg-bin/newsendmsg'), cgiData=allocate(cgi.length,cgi);
  task.add(0x18).writePointer(cgiData);task.add(0x20).writeU64(cgi.length);task.add(0x18+23).writeU8(128);
  const name=utf8('default-longlink');name.forEach((n,i)=>task.add(0x68+i).writeU8(n));task.add(0x68+23).writeU8(name.length);
  bufferAt(task.add(0x1c8),envelope);return task;
}
let hooks=0;
const sandbox={PROFILE:{},rpc:{},Uint8Array,Date,Map,BigInt,Number,Error,
  Process:{pageSize:4096,attachModuleObserver(){return {};},findRangeByAddress(address){
    const entry=heap.find(e=>address.value>=e.base.value&&address.value<e.base.value+BigInt(e.bytes.length));
    return entry?{base:entry.base,size:entry.bytes.length,protection:'rw-'}:null;
  }},Memory:{queryProtection(address){address.view(1);return 'rw-';}},
  Interceptor:{attach(){hooks++;throw Error('must_not_attach_in_mock');}}};
const context=vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../src/wechat_sender/native_diagnostic_probe.js'),'utf8'),context);
const run=code=>vm.runInContext(code,context);
let checks=0;const check=(name,body)=>{body();checks++;};
check('load/select are passive, bounded and do not reveal marker',()=>{
  assert.equal(hooks,0);assert.equal(sandbox.rpc.exports.select({recipient:'supplier',marker}).selected,false);
  assert.equal(sandbox.rpc.exports.select({recipient:'filehelper',marker}).selected,true);
  assert.equal(JSON.stringify(sandbox.rpc.exports.status()).includes(marker),false);
});
check('unselected private texts ignored entirely',()=>{
  sandbox.task=makeTask('PRIVATE_CHAT_CONTENT','supplier');run('request(task, 1)');
  assert.equal(sandbox.rpc.exports.status().request,null);
});
check('exact marker captures only safe metadata',()=>{
  sandbox.task=makeTask();run('request(task, 1); recordCommand(task)');
  const state=sandbox.rpc.exports.status();assert.equal(state.request.cgi.equals_expected,true);
  assert.equal(state.request.longlink.equals_expected,true);
  assert.equal(state.request.client_id_unsigned_bits,32);
  assert.equal(state.request.client_id_is_nonzero_uint32,true);
  assert.equal(state.request.timestamp_within_two_minutes,true);
  const serialized=JSON.stringify(state);
  for(const secret of [marker,'PRIVATE_AUTH_KEY_NEVER_OUTPUT','12345678901234567890',clientId.toString(),timestamp.toString()])
    assert.equal(serialized.includes(secret),false);
});
check('nested response reports zero and correlation without raw IDs or server text',()=>{
  const item=[...integer(1,0),...blob(2,blob(1,utf8('filehelper'))),...integer(3,3456789012n),
    ...integer(4,clientId),...integer(5,timestamp),...blob(9,utf8('PRIVATE_SERVER_TEXT'))];
  const base=[...integer(1,0),...blob(2,utf8('PRIVATE_SERVER_MESSAGE'))];
  const raw=[...blob(1,base),...integer(2,1),...blob(3,item),...integer(4,1)];
  const envelope=[...integer(1,522),...blob(2,raw),...blob(3,[]),...integer(4,0)];
  const address=allocate(40);bufferAt(address,envelope);sandbox.responseAddress=address;
  const result=run('response(responseAddress)');assert.equal(result.batch_return_zero,true);
  const fields=result.response_items[0].fields;
  assert.equal(fields.find(f=>f.field===1).zero,true);
  assert.equal(fields.find(f=>f.field===2).equals_filehelper_wxstring,true);
  assert.equal(fields.find(f=>f.field===4).equals_request_client_id,true);
  assert.equal(fields.find(f=>f.field===5).equals_request_timestamp,true);
  const serialized=JSON.stringify(result);
  for(const secret of ['PRIVATE_SERVER_TEXT','PRIVATE_SERVER_MESSAGE',clientId.toString(),timestamp.toString(),'3456789012'])
    assert.equal(serialized.includes(secret),false);
});
check('command-only window expires and is capped',()=>{
  run('diagnostic.command_window = []');
  for(let i=0;i<90;i++)run('recordCommand(task)');
  assert.equal(sandbox.rpc.exports.status().command_window.length,80);
  assert.equal(sandbox.rpc.exports.status().command_window_truncated,true);
  run('diagnostic.trace_until = 0; recordCommand(task)');
  assert.equal(sandbox.rpc.exports.status().command_window.length,80);
});
console.log(`Passed ${checks} passive diagnostic checks; no app/native access.`);
