// Native-only coroutine bridge. Version-specific target calls remain gated.
// This module must remain loaded until the owning WeChat process exits.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>

static_assert(sizeof(std::string) == 24);
static_assert(sizeof(void*) == 8);
using SharedRelease = void(*)(void*);
static SharedRelease native_release = nullptr;
struct NativeShared {
    void* object = nullptr;
    void* control = nullptr;
    NativeShared() = default;
    NativeShared(const NativeShared&) = delete;
    NativeShared& operator=(const NativeShared&) = delete;
    ~NativeShared() { if (control && native_release) native_release(this); }
};
static_assert(sizeof(NativeShared) == 16);
static_assert(!std::is_trivially_destructible_v<NativeShared>);
struct CoroutineOptions {
    std::string name;
    void* executor = nullptr;
    void* allocator = nullptr;
    uint64_t stack_size = 0;
    int32_t priority = -1;
    uint32_t flags = 0;
};
static_assert(sizeof(CoroutineOptions) == 0x38);
static_assert(offsetof(CoroutineOptions, executor) == 0x18);
static_assert(offsetof(CoroutineOptions, priority) == 0x30);

extern "C" __attribute__((visibility("default"))) uint64_t ws_abi_selftest() noexcept {
    std::string small("abc"), large(80, 'x');
    const auto* a = reinterpret_cast<const unsigned char*>(&small);
    const auto* b = reinterpret_cast<const unsigned char*>(&large);
    // Verify the alternate libc++ layout used by this exact native app.
    uint64_t result = sizeof(std::string) == 24 ? 1 : 0;
    result |= (a[23] == 3 && std::memcmp(a, "abc", 3) == 0) ? 2 : 0;
    uint64_t long_length = 0;
    std::memcpy(&long_length, b + 8, 8);
    result |= (b[23] & 0x80) && long_length == 80 ? 4 : 0;
    result |= sizeof(NativeShared) == 16 ? 8 : 0;
    result |= sizeof(CoroutineOptions) == 0x38 ? 16 : 0;
    return result;
}

using Create = NativeShared(*)(void(*)(void*),void*,void(*)(void*),const CoroutineOptions*);
using Schedule = void(*)(const NativeShared*,uint64_t);
using Getter = NativeShared(*)();
using ObjectGetter = NativeShared(*)(void*);
static uintptr_t target_base=0;
static NativeShared* pinned_manager=nullptr;
static Create native_create = nullptr;
static Schedule native_schedule = nullptr;
static Getter native_current = nullptr;
static Getter account_root_get = nullptr;
static ObjectGetter account_domain_get = nullptr;
static ObjectGetter message_service_get = nullptr;
static std::atomic<uint32_t> configured{0};
static void(*result_destroy)(void*)=nullptr;
struct NativeResult {
    alignas(8) unsigned char bytes[48];
    NativeResult()=default;
    NativeResult(const NativeResult&)=delete;
    ~NativeResult(){result_destroy(this);}
};
static_assert(sizeof(NativeResult)==48);
using SendService=NativeResult(*)(void*,const NativeShared*,uint32_t);
static Getter request_factory=nullptr;
static void*(*string_assign)(void*,const char*)=nullptr;
static SendService native_send=nullptr;
static void*(*session_get)()=nullptr;
static uint64_t(*identity_get)(void*)=nullptr;
struct Job {
    std::atomic<uint32_t> stage{0};
    std::atomic<uint32_t> flags{0};
    std::atomic<uint32_t> destroyed{0};
    std::atomic<uint32_t> error{0};
    uint32_t mode=0;
    std::string recipient;
    std::string text;
    uint64_t identity=0;
    std::atomic<uint32_t> local_id{0};
    std::atomic<int32_t> native_status{-1},native_error{-1};
};
// Only live or uncollected jobs occupy native storage. Handles never identify a
// different job, even after its registry entry has been retired.
constexpr size_t MAX_RETAINED_JOBS = 16;
struct JobRegistry {
    std::mutex mutex;
    std::map<uint64_t, std::shared_ptr<Job>> jobs;
    uint64_t next = 1;
};
// Avoid shutdown-order destructors while the application's worker can still run.
static JobRegistry* registry = new JobRegistry;
struct CallbackOwner { std::shared_ptr<Job> job; };
static std::shared_ptr<Job> find_job(uint64_t handle) {
    std::lock_guard<std::mutex> lock(registry->mutex);
    auto found = registry->jobs.find(handle);
    return found == registry->jobs.end() ? nullptr : found->second;
}
static uint64_t register_job(const std::shared_ptr<Job>& job) {
    std::lock_guard<std::mutex> lock(registry->mutex);
    if (registry->jobs.size() >= MAX_RETAINED_JOBS || registry->next == 0) return 0;
    const uint64_t handle = registry->next++;
    registry->jobs.emplace(handle, job);
    return handle;
}
static void smoke_body(void* value) noexcept {
    auto job = static_cast<CallbackOwner*>(value)->job;
    job->stage.store(2);
    try {
        auto current = native_current();
        if (!current.object || !current.control) { job->error.store(2); return; }
        job->flags.fetch_or(1);
        if (job->mode >= 1) {
            auto root = account_root_get();
            if (!root.object || !root.control) { job->error.store(3); return; }
            job->flags.fetch_or(2);
            auto domain = account_domain_get(root.object);
            if (!domain.object || !domain.control) { job->error.store(4); return; }
            job->flags.fetch_or(4);
            auto service = message_service_get(domain.object);
            if (!service.object || !service.control) { job->error.store(5); return; }
            job->flags.fetch_or(8);
            if(job->mode==2) {
                void* session=session_get();
                if(!session || !job->identity || identity_get(session)!=job->identity){job->error.store(8);return;}
                job->flags.fetch_or(16);
                auto request=request_factory();
                if(!request.object || !request.control){job->error.store(9);return;}
                auto* object=static_cast<unsigned char*>(request.object);
                string_assign(object+0x90,job->recipient.c_str());
                string_assign(object+0x5c8,job->text.c_str());
                *reinterpret_cast<uint32_t*>(object+0xe4)=1;
                *reinterpret_cast<uint64_t*>(object+0x170)=job->text.size();
                if(*reinterpret_cast<uint32_t*>(object+0xe8)!=0 ||
                    *reinterpret_cast<std::string*>(object+0x90)!=job->recipient ||
                    *reinterpret_cast<std::string*>(object+0x5c8)!=job->text){job->error.store(10);return;}
                job->flags.fetch_or(32);
                job->stage.store(4);
                {
                    auto result=native_send(service.object,&request,1);
                    job->stage.store(5);
                    int32_t first,second;std::memcpy(&first,result.bytes,4);std::memcpy(&second,result.bytes+4,4);
                    job->native_status.store(first);job->native_error.store(second);
                    void* payload;std::memcpy(&payload,result.bytes+0x20,8);
                    if(first==0 && second==0 && payload){
                        auto* record=static_cast<unsigned char*>(payload);
                        if(record[0x40]==1 && *reinterpret_cast<std::string*>(record)==job->recipient){
                            uint32_t local;std::memcpy(&local,record+0x1c,4);
                            if(local){job->local_id.store(local);job->flags.fetch_or(64);}
                        }
                    }
                }
                job->stage.store(6);
            }
        }
        job->stage.store(3);
    } catch (...) { job->error.store(1); }
}
static void smoke_destroy(void* value) noexcept {
    std::unique_ptr<CallbackOwner> owner(static_cast<CallbackOwner*>(value));
    // Native 6678aa0 calls this only after body() returns, and then clears its
    // destroy callback. Its context destructor never reads the argument again.
    // A reader may retire the registry immediately; this shared reference keeps
    // Job alive until this callback itself has finished using it.
    auto job = owner->job;
    job->destroyed.store(1, std::memory_order_release);
}

static uint64_t launch_job(std::shared_ptr<Job> job, void* executor, const char* name) noexcept {
    uint64_t handle = 0;
    bool scheduling_attempted = false;
    std::unique_ptr<CallbackOwner> owner;
    try {
        handle = register_job(job);
        if (!handle) return 0; // Nothing has been given to native code.
        owner = std::make_unique<CallbackOwner>(CallbackOwner{job});
        CoroutineOptions options;
        options.name = name;
        options.executor = executor;
        options.flags = 0x80000000;
        job->stage.store(1);
        auto context = native_create(smoke_body, owner.get(), smoke_destroy, &options);
        if (!context.object || !context.control) {
            job->error.store(6);
        } else {
            // Transfer before enqueue: the worker may run and destroy this
            // token before native_schedule returns to the caller.
            owner.release();
            scheduling_attempted = true;
            native_schedule(&context, 0);
        }
    } catch (...) {
        if (handle) job->error.store(7);
    }
    if (handle && !scheduling_attempted) {
        // No enqueue was attempted, and the context is already destroyed.
        // Static native cleanup does not call destroy(arg) before first start.
        owner.reset();
        job->destroyed.store(1, std::memory_order_release);
    }
    // If scheduling threw after accepting work, only smoke_destroy may release
    // its token. Retain the registry entry and report uncertainty until then.
    return handle;
}

extern "C" __attribute__((visibility("default"))) uint32_t ws_bridge_version() noexcept { return 2; }
// Addresses are provided only after the host validates the entire binary and
// every function fingerprint. No target code executes during configuration.
extern "C" __attribute__((visibility("default"))) int ws_configure(uintptr_t base) noexcept {
    uint32_t expected=0;
    if (!base || ws_abi_selftest()!=31 || !configured.compare_exchange_strong(expected,1)) return -1;
    target_base=base;
    native_release=reinterpret_cast<SharedRelease>(base+0x129f68);
    native_create=reinterpret_cast<Create>(base+0x667378c);
    native_schedule=reinterpret_cast<Schedule>(base+0x66738d4);
    native_current=reinterpret_cast<Getter>(base+0x6673848);
    account_root_get=reinterpret_cast<Getter>(base+0x466aca8);
    account_domain_get=reinterpret_cast<ObjectGetter>(base+0x1205740);
    message_service_get=reinterpret_cast<ObjectGetter>(base+0x268f370);
    result_destroy=reinterpret_cast<void(*)(void*)>(base+0x257824);
    request_factory=reinterpret_cast<Getter>(base+0x77bdd0);
    string_assign=reinterpret_cast<void*(*)(void*,const char*)>(base+0x713f808);
    native_send=reinterpret_cast<SendService>(base+0x317df64);
    session_get=reinterpret_cast<void*(*)()>(base+0x4669774);
    identity_get=reinterpret_cast<uint64_t(*)(void*)>(base+0x4670584);
    configured.store(2,std::memory_order_release);
    return 0;
}
// Only the retained, validated executor may start a native job.
extern "C" __attribute__((visibility("default"))) uint64_t ws_smoke(void* executor,uint32_t mode) noexcept {
    if (configured.load(std::memory_order_acquire)!=2 || !executor || mode>1) return 0;
    if (!pinned_manager || executor!=*static_cast<void**>(pinned_manager->object)) return 0;
    auto* stopping=reinterpret_cast<std::atomic<unsigned char>*>(static_cast<char*>(pinned_manager->object)+0x40);
    if(stopping->load(std::memory_order_acquire)!=0)return 0;
    try {
        auto job=std::make_shared<Job>(); job->mode=mode;
        return launch_job(std::move(job),executor,"wechat-mcp-native-smoke");
    }catch(...){return 0;}
}
extern "C" __attribute__((visibility("default"))) uint64_t ws_smoke_status(uint64_t handle) noexcept {
    auto job=find_job(handle); if(!job)return UINT64_MAX;
    // Acquire the completion publication before reading the result fields.
    const auto destroyed=job->destroyed.load(std::memory_order_acquire);
    return job->stage.load() | (uint64_t(job->flags.load())<<8) |
      (uint64_t(destroyed)<<24) | (uint64_t(job->error.load())<<32);
}
extern "C" __attribute__((visibility("default"))) int ws_release_job(uint64_t handle) noexcept {
    std::lock_guard<std::mutex> lock(registry->mutex);
    auto found=registry->jobs.find(handle);
    if(found==registry->jobs.end())return 1;
    if(found->second->destroyed.load(std::memory_order_acquire)!=1)return -1;
    registry->jobs.erase(found);
    return 0;
}
extern "C" __attribute__((visibility("default"))) uint64_t ws_job_metrics() noexcept {
    std::lock_guard<std::mutex> lock(registry->mutex);
    uint64_t pending=0,deferred=0;
    for(const auto& entry:registry->jobs){
        const auto& job=entry.second;
        if(job->destroyed.load(std::memory_order_acquire)!=1){
            ++pending; if(job->error.load()!=0)++deferred;
        }
    }
    return registry->jobs.size() | (pending<<16) | (deferred<<32);
}

extern "C" __attribute__((visibility("default"))) void* ws_bind_executor() noexcept {
    if(configured.load(std::memory_order_acquire)!=2 || pinned_manager)return nullptr;
    try {
        auto session_get=reinterpret_cast<void*(*)()>(target_base+0x4669774);
        auto owner_get=reinterpret_cast<ObjectGetter>(target_base+0x466ad74);
        void* session=session_get(); if(!session)return nullptr;
        // Deliberately retain one owner until process exit; do not execute a
        // static destructor after the app has torn down its runtime.
        auto* owner=new NativeShared(owner_get(session));
        if(!owner->object || !owner->control){delete owner;return nullptr;}
        void* executor=*static_cast<void**>(owner->object);
        auto* stopping=reinterpret_cast<std::atomic<unsigned char>*>(static_cast<char*>(owner->object)+0x40);
        if(!executor || stopping->load(std::memory_order_acquire)!=0){delete owner;return nullptr;}
        void** vtable=*static_cast<void***>(executor);
        if(reinterpret_cast<uintptr_t>(vtable[2])!=target_base+0x66617e4){delete owner;return nullptr;}
        pinned_manager=owner;
        return executor;
    }catch(...){return nullptr;}
}

extern "C" __attribute__((visibility("default"))) uint64_t ws_send_text(const char* recipient,const char* text,uint64_t identity) noexcept {
    if(configured.load(std::memory_order_acquire)!=2 || !pinned_manager || !recipient || !text || !identity)return 0;
    const size_t recipient_size=strnlen(recipient,513),text_size=strnlen(text,4097);
    if(!recipient_size || recipient_size>512 || !text_size || text_size>4096)return 0;
    auto* stopping=reinterpret_cast<std::atomic<unsigned char>*>(static_cast<char*>(pinned_manager->object)+0x40);
    if(stopping->load(std::memory_order_acquire)!=0)return 0;
    try {
        auto job=std::make_shared<Job>();job->mode=2;job->identity=identity;
        job->recipient.assign(recipient,recipient_size);job->text.assign(text,text_size);
        return launch_job(std::move(job),*static_cast<void**>(pinned_manager->object),"wechat-mcp-text-send");
    }catch(...){return 0;}
}
extern "C" __attribute__((visibility("default"))) uint64_t ws_send_field(uint64_t handle,uint32_t field) noexcept {
    auto job=find_job(handle);if(!job)return UINT64_MAX;
    switch(field){case 0:return job->local_id.load();case 1:return static_cast<uint32_t>(job->native_status.load());case 2:return static_cast<uint32_t>(job->native_error.load());default:return UINT64_MAX;}
}
