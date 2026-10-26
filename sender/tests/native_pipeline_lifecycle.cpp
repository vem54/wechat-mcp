// Standalone lifecycle tests. No app, Frida, target binary or network is used.
// Compile with clang++ -std=c++17 -pthread -fsanitize=address,undefined.
#include "../src/wechat_sender/native_pipeline.cpp"
#include <cassert>
#include <condition_variable>
#include <iostream>
#include <thread>
#include <vector>
#include <stdexcept>

struct FakeContext { void(*body)(void*); void* arg; void(*destroy)(void*); };
static std::mutex fake_mutex;
static std::vector<std::unique_ptr<FakeContext>> fake_contexts;
static bool fail_create=false,empty_create=false,throw_schedule=false,run_inline=false;
static std::atomic<unsigned> callback_count{0};
static NativeShared fake_current(){ return {reinterpret_cast<void*>(1),reinterpret_cast<void*>(2)}; }
static void fake_release(void*){}
static NativeShared fake_create(void(*body)(void*),void*arg,void(*destroy)(void*),const CoroutineOptions* options){
    assert(options->flags==0x80000000 && options->priority==-1);
    if(fail_create)throw std::runtime_error("create failed before enqueue");
    if(empty_create)return {};
    auto ctx=std::make_unique<FakeContext>(FakeContext{body,arg,destroy});auto* raw=ctx.get();
    std::lock_guard<std::mutex> lock(fake_mutex);fake_contexts.push_back(std::move(ctx));
    return {raw,raw};
}
static void run_context(FakeContext* ctx){
    ctx->body(ctx->arg);ctx->destroy(ctx->arg);callback_count.fetch_add(1);
}
static void fake_schedule(const NativeShared* context,uint64_t flags){
    assert(flags==0);
    if(run_inline)run_context(static_cast<FakeContext*>(context->object));
    if(throw_schedule)throw std::runtime_error("uncertain enqueue");
}
static FakeContext* last_context(){std::lock_guard<std::mutex> lock(fake_mutex);return fake_contexts.back().get();}
static void reset_fakes(){
    assert(ws_job_metrics()==0);
    fail_create=empty_create=throw_schedule=run_inline=false;
    std::lock_guard<std::mutex> lock(fake_mutex);fake_contexts.clear();
}
static uint64_t launch(std::weak_ptr<Job>* weak=nullptr){
    auto job=std::make_shared<Job>();if(weak)*weak=job;
    return launch_job(std::move(job),reinterpret_cast<void*>(3),"test");
}
static void assert_complete(uint64_t handle,uint32_t error=0){
    const auto state=ws_smoke_status(handle);
    assert(((state>>24)&255)==1 && (state>>32)==error);
    assert(ws_release_job(handle)==0);
    assert(ws_release_job(handle)==1);
    assert(ws_smoke_status(handle)==UINT64_MAX);
}
int main(){
    native_release=fake_release;native_create=fake_create;native_schedule=fake_schedule;native_current=fake_current;
    assert(ws_bridge_version()==2 && ws_abi_selftest()==31);
    // Completion can run before enqueue returns; registry owns evidence, token
    // owns callback state. Handles remain unique beyond the former 36 slots.
    uint64_t previous=0;
    for(unsigned i=0;i<10000;++i){
        run_inline=true;std::weak_ptr<Job> weak;const auto handle=launch(&weak);
        assert(handle>previous);previous=handle;assert(!weak.expired());
        assert_complete(handle);assert(weak.expired());reset_fakes();
    }
    // Return stage3 is insufficient; native destroy must publish completion.
    auto handle=launch();auto* ctx=last_context();ctx->body(ctx->arg);
    assert((ws_smoke_status(handle)&255)==3);assert(ws_release_job(handle)==-1);
    ctx->destroy(ctx->arg);assert_complete(handle);reset_fakes();
    // Pre-enqueue construction failures have no native owner and are reclaimable.
    for(bool empty:{false,true}){
        fail_create=!empty;empty_create=empty;std::weak_ptr<Job> weak;handle=launch(&weak);
        assert_complete(handle,empty?6:7);assert(weak.expired());reset_fakes();
    }
    // A schedule exception may mean accepted work. Never free its callback token
    // or registry entry until a later actual destroy callback arrives.
    throw_schedule=true;std::weak_ptr<Job> weak;handle=launch(&weak);
    assert(ws_release_job(handle)==-1);assert(!weak.expired());
    assert(ws_job_metrics()==(1ULL|(1ULL<<16)|(1ULL<<32)));
    run_context(last_context());assert_complete(handle,7);assert(weak.expired());reset_fakes();
    // An inline callback may finish before schedule throws: ownership is still
    // sound; report the uncertainty conservatively instead of resending.
    run_inline=throw_schedule=true;handle=launch(&weak);assert_complete(handle,7);assert(weak.expired());reset_fakes();
    // Bounded unresolved jobs apply backpressure without reusing a handle.
    std::vector<uint64_t> handles;
    for(size_t i=0;i<MAX_RETAINED_JOBS;++i){handle=launch();assert(handle);handles.push_back(handle);}
    assert(launch()==0 && (ws_job_metrics()&65535)==MAX_RETAINED_JOBS);
    for(size_t i=0;i<handles.size();++i){run_context(fake_contexts[i].get());assert_complete(handles[i]);}
    reset_fakes();
    // Race readers/retirement against callback publication. Lookup returns its
    // own shared reference, so erasing the registry cannot invalidate a reader.
    for(unsigned i=0;i<1000;++i){
        handle=launch(&weak);ctx=last_context();std::atomic<bool> start{false};
        std::thread worker([&]{while(!start.load()){}run_context(ctx);});
        std::thread reader([&]{while(!start.load()){}for(unsigned j=0;j<50;++j){(void)ws_smoke_status(handle);(void)ws_send_field(handle,0);}});
        start.store(true);
        while(ws_release_job(handle)==-1)std::this_thread::yield();
        worker.join();reader.join();assert(weak.expired());assert(ws_job_metrics()==0);reset_fakes();
    }
    std::cout<<"Native lifecycle: 10000 sequential + 1000 concurrent jobs, pre-enqueue failures, deferred cleanup, backpressure passed.\n";
}
