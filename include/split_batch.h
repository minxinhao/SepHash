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

// 将splithash的优化点分为：batch write(merge), depth-inline entry, append write/zero wait write, 
#define WO_WAIT_WRITE

namespace SPLIT_BATCH
{
constexpr uint64_t SEGMENT_SIZE = 1024;
constexpr uint64_t SLOT_PER_SEG = ((SEGMENT_SIZE) / (sizeof(uint64_t)+sizeof(uint8_t)));
constexpr uint64_t SLOT_BATCH_SIZE = 8;
constexpr uint64_t RETRY_LIMIT = (SLOT_PER_SEG/SLOT_BATCH_SIZE); // TODO : 后期试试改成其他较小的值
constexpr uint64_t MAX_MAIN_SIZE = 64 * SLOT_PER_SEG;
constexpr uint64_t MAX_FP_INFO = 256;
constexpr uint64_t INIT_DEPTH = 4;
constexpr uint64_t MAX_DEPTH = 16;
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
    uint8_t fp_2;
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
    void print(uint64_t slot_id = -1)
    {
        if(slot_id!=-1) printf("slot_id:%lu\t", slot_id);
        printf("fp:%x\t", fp);
        printf("fp_2:%x\t", fp_2);
        printf("len:%d\t", len);
        printf("sign:%d\t", sign);
        printf("dep:%d\t", dep);
        printf("offset:%lx\t", offset);
        printf("size:%ld\n", sizeof(Slot));
    }
}__attribute__((aligned(1)));

struct Slice
{
    uint64_t len;
    char *data;
};

struct KVBlock
{
    uint64_t k_len;
    uint64_t v_len;
    // uint64_t version;
    char data[0]; // 变长数组，用来保证KVBlock空间上的连续性，便于RDMA操作
}__attribute__((aligned(1)));

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
    uint64_t fp_bitmap[16]; // 16*64 = 1024,代表10bits fp的出现情况；整个CurSeg大约会出现（1024/8=128）个FP，因此能极大的减少search对CurSeg的访问
}__attribute__((aligned(1)));

struct CurSeg
{
    uint64_t split_lock;
    CurSegMeta seg_meta;
    Slot slots[SLOT_PER_SEG];
}__attribute__((aligned(1)));

struct MainSeg
{
    Slot slots[0];
}__attribute__((aligned(1)));

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
} __attribute__((aligned(1)));

struct Directory
{
    uint64_t global_depth;   // number of segment
    DirEntry segs[DIR_SIZE]; // Directory use MSB and is allocated enough space in advance.
    uint64_t start_cnt;      // 为多客户端同步保留的字段，不影响原有空间布局

    void print(){
        log_err("Global_Depth:%lu",global_depth);
        for(uint64_t i = 0 ; i < (1<<global_depth) ; i++){
            log_err("Entry %lx : local_depth:%lu cur_seg_ptr:%lx main_seg_ptr:%lx main_seg_lne:%lx",i,segs[i].local_depth,segs[i].cur_seg_ptr,segs[i].main_seg_ptr,segs[i].main_seg_len);
        }
    }
} __attribute__((aligned(1)));

struct SlotOffset
{
    // 记录每个CurSeg中上次insert访问到的slot offset
    bool sign;
    uint8_t offset; 
    uint64_t main_seg_ptr; 
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
    task<std::tuple<uintptr_t, uint64_t>> search(Slice *key, Slice *value);
    task<> update(Slice *key, Slice *value);
    task<> remove(Slice *key);

  private:
    task<> sync_dir();
    task<uintptr_t> check_gd(uint64_t segloc);

    task<> Split(uint64_t seg_loc, uintptr_t seg_ptr, CurSegMeta *old_seg_meta);
    void merge_insert(Slot *data, uint64_t len, Slot *old_seg, uint64_t old_seg_len, Slot *new_seg);
    
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
    uint64_t key_off;

    // Statistic
    Perf perf;
    uint64_t op_cnt;
    uint64_t miss_cnt;
    uint64_t retry_cnt;

    // Data part
    SlotOffset offset[DIR_SIZE] ; // 记录当前CurSeg中的freeslot开头？仅作参考，还是每个cli进行随机read
                        // 还是随机read吧，使用一个固定的序列？保存在本地，免得需要修改远端的。
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