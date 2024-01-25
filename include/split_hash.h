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

#define WO_WAIT_WRITE

namespace SPLIT_HASH
{
constexpr uint64_t SEGMENT_SIZE = 1024;
constexpr uint64_t SLOT_PER_SEG = ((SEGMENT_SIZE - 4 * sizeof(uint64_t)) / 8);
constexpr uint64_t MAX_MAIN_SIZE = 16 * SLOT_PER_SEG;
constexpr uint64_t MAX_FP_INFO = 256;
constexpr uint64_t INIT_DEPTH = 4;
constexpr uint64_t MAX_DEPTH = 14;
constexpr uint64_t DIR_SIZE = (1 << MAX_DEPTH);
constexpr uint64_t ALIGNED_SIZE = 64;             // aligned size of len bitfield in DepSlot
constexpr uint64_t dev_mem_size = (1 << 10) * 64; // 64KB的dev mem，用作lock
constexpr uint64_t num_lock =
    (dev_mem_size - sizeof(uint64_t)) / sizeof(uint64_t); // Lock数量，client对seg_id使用hash来共享lock

struct Slot
{
    uint8_t fp : 8;
    uint8_t len : 3;
    uint8_t sign : 1; // 用来表示split delete信息
    uint8_t dep : 4;
    uint64_t offset : 48;
    operator uint64_t()
    {
        return *(uint64_t *)this;
    }
    Slot(uint64_t u)
    {
        *this = *(Slot *)(&u);
    }
    bool operator<(const Slot &a) const
    {
        return fp < a.fp;
    }
    void print()
    {
        printf("fp:%x\t", fp);
        printf("len:%d\t", len);
        printf("sign:%d\t", sign);
        printf("dep:%d\t", dep);
        printf("offset:%lu\t", offset);
        printf("size:%ld\n", sizeof(Slot));
    }
} __attribute__((aligned(8)));

struct Slice
{
    uint64_t len;
    char *data;
};

struct KVBlock
{
    uint64_t k_len;
    uint64_t v_len;
    uint64_t version;
    char data[0]; // 变长数组，用来保证KVBlock空间上的连续性，便于RDMA操作
};

template <typename Alloc>
    requires Alloc_Trait<Alloc, uint64_t>
KVBlock *InitKVBlock(Slice *key, Slice *value, Alloc *alloc)
{
    KVBlock *kv_block = (KVBlock *)alloc->alloc(3 * sizeof(uint64_t) + key->len + value->len);
    kv_block->k_len = key->len;
    kv_block->v_len = value->len;
    memcpy(kv_block->data, key->data, key->len);
    memcpy(kv_block->data + key->len, value->data, value->len);
    return kv_block;
}

struct CurSegMeta{
    uint8_t sign : 1; // 实际中的split_lock可以和sign、depth合并，这里为了不降rdma驱动版本就没有合并。
    uint64_t local_depth : 63;
    uintptr_t main_seg_ptr;
    uintptr_t main_seg_len;
}__attribute__((aligned(8)));

struct CurSeg
{
    uint64_t split_lock;
    uint8_t sign : 1; // 实际中的split_lock可以和sign、depth合并，这里为了不降rdma驱动版本就没有合并。
    uint64_t local_depth : 63;
    uintptr_t main_seg_ptr;
    uintptr_t main_seg_len;
    Slot slots[SLOT_PER_SEG];
}__attribute__((aligned(8)));

struct MainSeg
{
    Slot slots[0];
} __attribute__((aligned(8)));

/// @brief 记录MainSeg中，偏差超过32处的fp和offset
struct FpInfo{ 
    uint8_t num; // 数量 
    operator uint64_t()
    {
        return *(uint64_t *)this;
    }
}__attribute__((aligned(1)));

struct DirEntry
{
    // TODO : 实际上只需要用5 bits，为了方便ptr统一48，所以这里仍保留16bits
    uint64_t local_depth ; 
    uintptr_t cur_seg_ptr ;
    uintptr_t main_seg_ptr ;
    uint64_t main_seg_len ;
    FpInfo fp[MAX_FP_INFO];
    bool operator==(const DirEntry &other) const
    {
        return cur_seg_ptr == other.cur_seg_ptr && main_seg_ptr == other.main_seg_ptr &&
               main_seg_len == other.main_seg_len;
    }
} __attribute__((aligned(8)));

struct Directory
{
    uint64_t global_depth;   // number of segment
    DirEntry segs[DIR_SIZE]; // Directory use MSB and is allocated enough space in advance.
    uint64_t start_cnt;      // 为多客户端同步保留的字段，不影响原有空间布局

    void print(){
        log_err("Global_Depth:%lu",global_depth);
        for(uint64_t i = 0 ; i < (1<<global_depth) ; i++){
            log_err("Entry %lu : local_depth:%lu cur_seg_ptr:%lx main_seg_ptr:%lx main_seg_lne:%lx",i,segs[i].local_depth,segs[i].cur_seg_ptr,segs[i].main_seg_ptr,segs[i].main_seg_len);
        }
    }
} __attribute__((aligned(8)));

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

    task<> insert(Slice *key, Slice *value);
    task<bool> search(Slice *key, Slice *value);
    task<> update(Slice *key, Slice *value);
    task<> remove(Slice *key);

  private:
    task<> sync_dir();

    task<> Split(uint64_t seg_loc, uintptr_t seg_ptr, CurSeg *old_seg);

    // Global/Local并行的方式造成的等待冲突太高了，就使用简单的单个lock
    task<int> LockDir();
    task<> UnlockDir();

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

    // Statistic
    Perf perf;
    uint64_t op_cnt;

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