/* Native send workflow: request creation, Mac history insertion, and transport.
 * No UI automation or database writes. All yielding code stays in the C++ shim.
 * Code remains pinned until app exit; individual completed jobs are reclaimed.
 */
'use strict';
const MAX_UNACKNOWLEDGED=64,MAX_RECENT=64;
const operations=new Map(),recent=new Map();
let highestSequence=0;
let prepared=false,pinned=false,preparing=false,diagnostic=null,identity=null,permit=null;
let lib,executor,abi,configure,bind,smoke,packed,sendText,field,releaseJob,jobMetrics,sessionGet,identityGet;
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function fail(code){throw Error(code);}
function textLength(value,max){
 if(typeof value!=='string'||!value||value.includes('\0'))fail('invalid_text');
 let size;try{size=unescape(encodeURIComponent(value)).length;}catch(_){fail('invalid_text');}
 if(size>max)fail('invalid_text');return size;
}
function validateOperation(operation,sequence){
 if(typeof operation!=='string'||!operation||operation.length>128)fail('invalid_operation_id');
 if(!Number.isSafeInteger(sequence)||sequence<=0)fail('invalid_dispatch_sequence');
}
function currentIdentity(){const session=sessionGet();if(session.isNull())fail('account_not_ready');const now=identityGet(session);if(now.compare(0)===0)fail('account_not_ready');return now;}
function account(){const now=currentIdentity();if(identity!==null&&now.compare(identity)!==0)fail('prepared_account_changed');return now;}
function nativeState(handle){
 const n=BigInt(packed(handle).toString());if(n===0xffffffffffffffffn)fail('native_job_missing');
 return {stage:Number(n&255n),flags:Number((n>>8n)&65535n),destroyed:Number((n>>24n)&255n),error:Number(n>>32n)};
}
function correlated(op){return {...op.result,operation_known:true,dispatch_sequence:op.sequence};}
function result(op){
 if(op.handle===null)return correlated(op);
 try{
  const state=nativeState(op.handle);
  if(state.destroyed===1){
   const local=Number(field(op.handle,0).toString()),status=Number(field(op.handle,1).toString()),error=Number(field(op.handle,2).toString());
   const good=state.stage===3&&state.flags===127&&state.error===0&&status===0&&error===0&&local>0&&local<2**32;
   // Copy evidence before retiring the native registry entry. The native callback
   // retains its own shared reference until it has returned.
   op.result=good?{status:'native_pipeline_completed',completed:true,native_status:0,native_error:0,local_id:local,recipient_correlated:true,request_correlated:true}
    :{status:'outcome_unknown',completed:true,diagnostic_code:'native_completion_unverified'};
   if(releaseJob(op.handle)!==0)fail('native_cleanup_failed');
   op.handle=null;op.done=true;
  }else if(state.error!==0){
   op.result={status:'outcome_unknown',completed:false,diagnostic_code:'native_cleanup_pending'};
  }
 }catch(error){
  diagnostic=error.message==='native_job_missing'?'native_job_missing':'native_cleanup_failed';
  op.result={status:'outcome_unknown',completed:false,diagnostic_code:diagnostic};
 }
 return correlated(op);
}
function metrics(){
 if(!jobMetrics)return {native_retained_jobs:0,native_pending_jobs:0,deferred_cleanup_count:0};
 const n=BigInt(jobMetrics().toString());
 return {native_retained_jobs:Number(n&65535n),native_pending_jobs:Number((n>>16n)&65535n),deferred_cleanup_count:Number((n>>32n)&65535n)};
}
function status(){
 let inflight=0;for(const op of operations.values()){result(op);if(!op.done)inflight++;}
 let bound=false;try{if(prepared){account();bound=true;}}catch(error){diagnostic=error.message;}
 const ready=prepared&&bound&&!diagnostic;
 return {ready,sends_enabled:ready&&inflight===0&&operations.size<MAX_UNACKNOWLEDGED,phase:prepared?'prepared':preparing?'preparing':'blocked',
 diagnostic_code:diagnostic,can_detach:!pinned,inflight_count:inflight,operation_capacity_remaining:MAX_UNACKNOWLEDGED-operations.size,
 unacknowledged_count:operations.size,recent_result_count:recent.size,operation_lifetime_limit:null,
 highest_dispatch_sequence:highestSequence,...metrics(),
 lifetime_policy:'pinned_until_app_exit',completion_policy:'native_send_result_no_delivery_claim',outgoing_local_history_reconciled:false,
 outgoing_history_path:'native_app_send_workflow'};
}
async function prepare(){
 if(prepared||preparing||pinned)return status();preparing=true;
 try{
  if(PROFILE.runtime_verified!==true||PROFILE.sending_permitted!==true||PROFILE.send_framing_verified!==true||PROFILE.native_pipeline?.enabled!==true)fail('native_pipeline_not_enabled');
  if(Process.arch!=='arm64')fail('unsupported_architecture');
  const mod=Process.enumerateModules().find(m=>m.name==='wechat.dylib');if(!mod)fail('native_module_not_found');
  for(const entry of Object.values(PROFILE.native_pipeline.functions)){
   const actual=Array.from(new Uint8Array(mod.base.add(entry.offset).readByteArray(16))).map(x=>x.toString(16).padStart(2,'0')).join('');
   if(actual!==entry.first16bytes)fail('native_instruction_mismatch');
  }
  sessionGet=new NativeFunction(mod.base.add('0x4669774'),'pointer',[]);
  identityGet=new NativeFunction(mod.base.add('0x4670584'),'uint64',['pointer']);
  const initial=currentIdentity();
  lib=Module.load(PIPELINE_LIBRARY_PATH);Script.pin();pinned=true;
  const fn=(name,ret,args)=>new NativeFunction(lib.getExportByName(name),ret,args,{scheduling:'cooperative'});
  abi=fn('ws_abi_selftest','uint64',[]);if(abi().toString()!=='31'||fn('ws_bridge_version','uint',[])()!==2)fail('native_abi_mismatch');
  configure=fn('ws_configure','int',['pointer']);if(configure(mod.base)!==0)fail('native_configure_failed');
  bind=fn('ws_bind_executor','pointer',[]);executor=bind();if(executor.isNull())fail('native_executor_unavailable');
  smoke=fn('ws_smoke','uint64',['pointer','uint']);packed=fn('ws_smoke_status','uint64',['uint64']);
  sendText=fn('ws_send_text','uint64',['pointer','pointer','uint64']);field=fn('ws_send_field','uint64',['uint64','uint']);
  releaseJob=fn('ws_release_job','int',['uint64']);jobMetrics=fn('ws_job_metrics','uint64',[]);
  for(const mode of [0,1]){
   const handle=smoke(executor,mode);if(BigInt(handle.toString())===0n)fail('native_startup_check_rejected');
   let observed;
   for(let n=0;n<200;n++){observed=nativeState(handle);if(observed.destroyed)break;await sleep(10);}
   if(observed.destroyed===1&&releaseJob(handle)!==0)fail('native_cleanup_failed');
   if(observed.stage!==3||observed.flags!==(mode===0?1:15)||observed.destroyed!==1||observed.error!==0)fail('native_startup_check_failed');
  }
  if(currentIdentity().compare(initial)!==0)fail('account_changed_during_prepare');
  identity=initial;prepared=true;diagnostic=null;
 }catch(error){diagnostic=String(error.message).match(/^[a-z_]+$/)?error.message:'native_prepare_failed';}
 finally{preparing=false;}
 return status();
}
function arm(options){
 if(!status().ready)fail('sender_not_ready');account();
 textLength(options.recipient,512);if(/[\x00-\x1f]/.test(options.recipient))fail('invalid_recipient');
 textLength(options.text,4096);validateOperation(options.operation_id,options.dispatch_sequence);
 if(options.ttl_seconds!==60)fail('invalid_permit');
 permit={recipient:options.recipient,text:options.text,operation:options.operation_id,sequence:options.dispatch_sequence,expires:Date.now()+60000};return {armed:true};
}
function sendnative(target,text,operation,sequence){
 validateOperation(operation,sequence);
 const old=operations.get(operation)||recent.get(operation);
 if(old){
  if(old.payload!==JSON.stringify([target,text])||old.sequence!==sequence)fail('operation_payload_mismatch');
  return result(old);
 }
 // The host's durable journal assigns a stable, increasing sequence BEFORE arm.
 // Forgotten sequences cannot send again after bounded recent results expire.
 if(sequence<=highestSequence)fail('dispatch_sequence_already_consumed');
 const state=status();if(!state.ready||state.inflight_count||operations.size>=MAX_UNACKNOWLEDGED)fail('native_not_available');
 textLength(target,512);textLength(text,4096);account();
 if(!permit||permit.recipient!==target||permit.text!==text||permit.operation!==operation||permit.sequence!==sequence||Date.now()>permit.expires)fail('intent_permit_required');
 permit=null;highestSequence=sequence;
 const op={sequence,payload:JSON.stringify([target,text]),handle:null,done:false,result:{status:'outcome_unknown',completed:false,diagnostic_code:'native_dispatch_uncertain'}};
 operations.set(operation,op);
 try{
  const recipient=Memory.allocUtf8String(target),content=Memory.allocUtf8String(text);
  const handle=sendText(recipient,content,identity);
  if(BigInt(handle.toString())===0n){op.done=true;op.result={status:'rejected',completed:true,diagnostic_code:'native_send_not_started'};}
  else {op.handle=handle;op.result={status:'submitted',completed:false,diagnostic_code:'native_pipeline_pending'};}
 }catch(_){op.done=true;op.result={status:'outcome_unknown',completed:true,diagnostic_code:'native_dispatch_uncertain'};diagnostic='native_dispatch_uncertain';}
 return result(op);
}
function acknowledge(operation,sequence){
 validateOperation(operation,sequence);
 const op=operations.get(operation)||recent.get(operation);
 if(!op)return {acknowledged:sequence<=highestSequence,operation_known:false};
 if(op.sequence!==sequence)fail('operation_sequence_mismatch');
 result(op);if(!op.done)return {acknowledged:false,operation_known:true,dispatch_sequence:sequence};
 if(operations.has(operation)){
  operations.delete(operation);recent.set(operation,op);
  while(recent.size>MAX_RECENT)recent.delete(recent.keys().next().value);
 }
 return {acknowledged:true,operation_known:true,dispatch_sequence:sequence};
}
rpc.exports={prepare,status,arm,disarm(){permit=null;return {armed:false};},sendnative,acknowledge,
 getresult(operation){const op=operations.get(operation)||recent.get(operation);return op?result(op):{status:'outcome_unknown',operation_known:false,completed:false,diagnostic_code:'unknown_operation'};}};
