#pragma once
#include "aiordma.h"
#include "alloc.h"
#include "config.h"
#include "hash.h"
#include "kv_trait.h"
#include "perf.h"
#include "search.h"
#include <cassert>
#include <chrono>
#include <fcntl.h>
#include <map>
#include <math.h>
#include <tuple>
#include <vector>
#include <atomic>

#define WO_WAIT_WRITE

namespace ClevelSingleFilter
{

// According RACE's Evaluation : 8 slots per main or overflow bucket in DrTM cluster hashing
constexpr uint64_t BUCKET_SIZE = 8;

// 初始DIR_SIZE允许的Slot数目是SplitHash的(1+MAX_SEG_LEN)*(SLOT_PER_SEG)/(BUCKET_SIZE*3)
// 以 MAX_SEG_LEN:16 SLOT_PER_SEG:110为例，比例为(1+16)*110/(8*3) = 78
constexpr uint64_t DIR_RATIO = 128;
constexpr uint64_t INIT_TABLE_SIZE = (1 << 4) * DIR_RATIO;
// constexpr uint64_t INIT_TABLE_SIZE = (1 << 14) * DIR_RATIO;
// DIR空间开销为(1 << 16) * 64 * 10 /(1<<20) = 40 MB
constexpr uint64_t MAX_TABLE_SIZE = (1 << 16) * DIR_RATIO;
constexpr uint64_t MAX_LEVEL = 16;
// Move Data和清空远端Bucket Array时，批量读取的Bucket的数量
constexpr uint64_t zero_size = (1 << 4) * DIR_RATIO;
constexpr uint64_t bucket_batch_size = zero_size ; 

// 64KB的dev mem，用作lock
constexpr uint64_t dev_mem_size = (1 << 10) * 64;
// aligned size of len bitfield in DepSlot
constexpr uint64_t ALIGNED_SIZE = 64;

struct Slice
{
    uint64_t len;
    char *data;
};

struct KVBlock
{
    uint64_t k_len;
    uint64_t v_len;
    char data[0];
    void print(const char* desc = nullptr){
        if(desc!=nullptr) log_err("%s klen:%lu key:%lu vlen:%lu value:%s",desc,k_len,*(uint64_t*)data,v_len,data+sizeof(uint64_t));
        else log_err("klen:%lu key:%lu vlen:%lu value:%s",k_len,*(uint64_t*)data,v_len,data+sizeof(uint64_t));
    }
} __attribute__((aligned(1)));

template <typename Alloc>
    requires Alloc_Trait<Alloc, uint64_t>
KVBlock *InitKVBlock(Slice *key, Slice *value, Alloc *alloc)
{
    KVBlock *kv_block = (KVBlock *)alloc->alloc(2 * sizeof(uint64_t) + key->len + value->len);
    kv_block->k_len = key->len;
    kv_block->v_len = value->len;
    memcpy(kv_block->data, key->data, key->len);
    memcpy(kv_block->data + key->len, value->data, value->len);
    return kv_block;
}

struct Entry
{
    uint8_t len : 8;
    uint8_t fp : 8;
    uint64_t offset : 48;
    operator uint64_t()
    {
        return *(uint64_t *)this;
    }
    void print(const char* desc = nullptr){
        if(desc!=nullptr) log_err("%s len:%d fp:%x offset:%lx",desc,len,fp,offset);
        else log_err("len:%d fp:%x offset:%lx",len,fp,offset);
    }
} __attribute__((aligned(1)));

struct Bucket
{
    Entry entrys[BUCKET_SIZE];
    uint64_t filter[2]; // 直接使用filter[0]作为epoch吧，因为每次修改都会更改filter的
} __attribute__((aligned(1)));


struct LevelTable
{
    uintptr_t up;
    uint64_t capacity;
    Bucket buckets[0];
} __attribute__((aligned(1)));


struct Directory
{
    uint64_t is_resizing;    
    uintptr_t first_level;
    uintptr_t last_level;
    // uint64_t dir_lock; //因为使用了静态的空间分配，这里还是需要使用一个DirLock,实际测试中对性能影响很小；

    // 为多客户端同步保留的字段，不影响原有空间布局
    uint64_t start_cnt;
    void print(const char* desc = nullptr){
       if(desc!=nullptr) log_err("%s is_resizing:%lu first_level:%lx last_level:%lx",desc,is_resizing,first_level,last_level);
       else log_err("is_resizing:%lu first_level:%lx last_level:%lx",is_resizing,first_level,last_level);
    }
} __attribute__((aligned(1)));

class Client : public BasicDB
{
public:
    Client(Config &config, ibv_mr *_lmr, rdma_client *_cli, rdma_conn *_conn, rdma_conn *_wowait_conn,
            uint64_t _machine_id, uint64_t _cli_id, uint64_t _coro_id);

    Client(const Client &) = delete;

    ~Client();

    // Used for sync operation and test
    task<> start(uint64_t total);
    task<> stop();
    task<> reset_remote();
    task<> cal_utilization();

    task<> insert(Slice *key, Slice *value);
    task<bool> search(Slice *key, Slice *value);
    task<> update(Slice *key, Slice *value);
    task<> remove(Slice *key);

    // 用来在Resize的时候Move数据
    task<> rehash(std::atomic_bool& exit_flag);
    task<bool> check_exit();
private:

    // rdma structs
    rdma_client *cli;
    rdma_conn *conn;
    rdma_conn *wo_wait_conn;
    rdma_rmr seg_rmr;
    rdma_rmr lock_rmr;
    struct ibv_mr *lmr;

    Alloc alloc;
    RAlloc ralloc;
    uint64_t machine_id;
    uint64_t cli_id;
    uint64_t coro_id;
    uint64_t key_num;
    uint64_t key_off;

    // Statistic
    Perf perf;
    uint64_t op_cnt;
    uint64_t miss_cnt;
    uint64_t retry_cnt;

    // Data part
    Directory *dir;
};

class Server : public BasicDB
{
public:
    Server(Config &config);
    ~Server();

private:
    void Init();

    rdma_dev dev;
    rdma_server ser;
    struct ibv_mr *seg_mr;
    ibv_dm *lock_dm; // Locks for Segments
    ibv_mr *lock_mr;
    char *mem_buf;

    Alloc alloc;
    Directory *dir;
};

} // namespace SPLIT_HASH