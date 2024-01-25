#pragma once
#include <fcntl.h>
#include <math.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iterator>
#include <map>
#include <tuple>
#include <vector>

#include "aiordma.h"
#include "alloc.h"
#include "config.h"
#include "hash.h"
#include "kv_trait.h"
#include "perf.h"
#include "search.h"

namespace PlushSingleFilter
{
// Plush代码中使用了ENTRY_IDX +
// BUCKET_IDX的配置，实际上就是增大了初始HashTable大小；
// 这里为了保证公平性，和其他HashTable的初始大小保持一致
// 还是不行；Plush使用了类似Bucket List又不太像的方式；
// ENTRY_IDX对应一组BUCKET，这一组中任何一个BUCKET满了之后就进行rehash

// number of groups in first level
// 为了和其他table初始大小保持一致：((1+16)*110*16)/(16*16) = 117 ~ 128 = 1<<7
constexpr uint64_t init_group_bits = 7;
constexpr uint64_t init_group_num = (1 << init_group_bits);
// number of bucket in every group
constexpr uint64_t bucket_per_group = (1 << 4);
// number of entry in every bucket
constexpr uint64_t entry_per_bucket = 16;
// number of entry in every group
constexpr uint64_t entry_per_group = entry_per_bucket * bucket_per_group;

// 固定fanout为2，论文也说的2，不知道为啥代码里面用的16
constexpr uint64_t fanout_bits = 4;
constexpr uint64_t fanout = (1 << fanout_bits);
// constexpr uint64_t max_level = (fanout == 2) ? 12 : 4;
constexpr uint64_t max_group_num = (fanout == 2) ? 524160 : 559232; // 134184960:143163392
constexpr uint64_t first_level_group_num = init_group_num;
constexpr uint64_t sec_level_group_num = fanout * first_level_group_num;
constexpr uint64_t bot_group_num = (max_group_num - first_level_group_num - sec_level_group_num);

// aligned size of len bitfield in DepSlot
constexpr uint64_t ALIGNED_SIZE = 64;
constexpr uint64_t KEY_SIZE = 8;
constexpr uint64_t KEY_VALUE_SIZE = (17 * ALIGNED_SIZE);

struct Slice
{
    uint64_t len;
    char *data;

    bool operator==(const Slice &other) const
    {
        if (len != other.len)
            return false;
        return (memcmp(data, other.data, len) == 0);
    }

    void print(uint64_t cli_id, uint64_t coro_id, uint64_t line = 0)
    {
        if (len == sizeof(uint64_t))
        {
            log_err("[%lu:%lu]line:%lu key:%lu", cli_id, coro_id, line, *(uint64_t *)data);
        }
        else
        {
            log_err("[%lu:%lu]line:%lu len:%lu data:%s", cli_id, coro_id, line, len, data);
        }
    }
};

struct KVBlock
{
    uint64_t k_len;
    uint64_t v_len;
    char data[0];
    void print(const char *desc = nullptr)
    {
        if (desc != nullptr)
            log_err("%s klen:%lu key:%lu vlen:%lu value:%s", desc, k_len, *(uint64_t *)data, v_len,
                    data + sizeof(uint64_t));
        else
            log_err("klen:%lu key:%lu vlen:%lu value:%s", k_len, *(uint64_t *)data, v_len, data + sizeof(uint64_t));
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
    void print(const char *desc = nullptr) const
    {
        if (desc != nullptr)
            log_err("%s len:%d fp:%x offset:%lx", desc, len, fp, offset);
        else
            log_err("len:%d fp:%x offset:%lx", len, fp, offset);
    }
} __attribute__((aligned(1)));

struct Bucket
{
    Entry entrys[entry_per_bucket];
    void print()
    {
        for (auto &entry : entrys)
        {
            entry.print();
        }
    }
} __attribute__((aligned(1)));

// 用于Level1，存放更大的filter，代表更低的false positive rates
struct SecBucketPointer
{
    // __uint128_t filter1; // 存放bloom filter计算得到的数组
    // __uint128_t filter2; // 存放bloom filter计算得到的数组
    uint64_t filter[4];
    uintptr_t buc_ptr;
    void print()
    {
        log_err("filter1_0:%lx filter1_1:%lx filter2_0:%lx filter2_1:%lx buc_ptr:%lx", filter[0], filter[1], filter[2],
                filter[3], buc_ptr);
    }
} __attribute__((aligned(1)));

struct SecGroupPointer
{
    uint64_t size;
    uint64_t epoch;
    SecBucketPointer bucket_pointers[bucket_per_group];

    void print()
    {
        log_err("size:%lu epoch:%lu", size, epoch);
        for (auto &e : bucket_pointers)
        {
            // if(e.buc_ptr==0) break;
            e.print();
        }
    }
} __attribute__((aligned(1)));

struct BucketPointer
{
    // __uint128_t filter; // 存放bloom filter计算得到的数组
    uint64_t filter[2];
    uintptr_t buc_ptr;
    void print()
    {
        log_err("filter_0:%lx filter_1:%lx buc_ptr:%lx", filter[0], filter[1], buc_ptr);
    }
} __attribute__((aligned(1)));

struct InnerGroupPointer
{
    uint64_t size;
    uint64_t epoch;
    BucketPointer bucket_pointers[bucket_per_group];
    void print()
    {
        log_err("size:%lu epoch:%lu", size, epoch);
        for (auto &e : bucket_pointers)
        {
            // if(e.buc_ptr==0) break;
            e.print();
        }
    }
} __attribute__((aligned(1)));

struct TopPointer
{
    uint64_t lock;
    uint64_t epoch;
    uint64_t size[bucket_per_group];
    // Top Bucket is At fixed postion
    void print()
    {
        log_err("lock:%lu epoch:%lu", lock, epoch);
        for (uint64_t i = 0; i < bucket_per_group; i++)
        {
            printf("size[%lu]:%lu ", i, size[i]);
        }
        printf("\n");
    }
} __attribute__((aligned(1)));

// 出于公平起见，为Plush增加Directory Cache;
// 但是考虑到directory中存放每个bucket的size而非指针，被频繁更新，因为缓存收益小于开销。
// 因而选择统一增加filer cache

// 带directory cache和不带direcoty cache的写成两个版本
// 暂时不缓存了，没啥收益
// 是否缓存第一层的directory
constexpr uint64_t directory_cache_flag = 0;
// 缓存第一层的directory : lock,epoch,sizes[bucket_per_group]
constexpr uint64_t first_directory_cache_size = init_group_num * (16 + 8 * bucket_per_group);
// search过程中是否使用filter cache
constexpr bool use_filter_cache = true;

struct DirecotryCache
{
    uint64_t cur_level;
    TopPointer first_level[init_group_num];
} __attribute__((aligned(1)));

// 为了适应灵活的cache大小，同时不使用map等结构，以及方便灵活跨层次
// 固定缓存第二层（第一层没有filter），然后根据剩下的cache——size顺序缓存bucket
// 为了判断缓存的一致性，同多读取
// 1. 单纯测试缓存的加速效果，保证filter cache都是有效的
// 2. cache中额外缓存size；通过比较远端size和本地size（或者epoch），来判断数据是否失效
// 2.1 还是缓存epoch吧，能保证正确性
// 2.2 还是同步缓存buc_ptr吧，这样减少多次rdma，代码也免得重复
struct SecCacheEntry
{
    // uint64_t size;
    uint64_t epoch;
    uint64_t filter[bucket_per_group][4];
    uint64_t buc_ptr[bucket_per_group];
};

struct BotCacheEntry
{
    // uint64_t size;
    uint64_t epoch;
    uint64_t filter[bucket_per_group][2];
    uint64_t buc_ptr[bucket_per_group];
};

// 按照评委的建议：为高层设置较低的false positive
// rates；然后优先缓存高层次的filter。
// 这里为了方便传输和对齐，为第一层设置256bits的filter，第二层设置128bits的filter，第三层及以后设置64bits的filter
// 总共的cache—size减去第一层directory用去的空间
constexpr uint64_t filter_cache_size = ((1 << 20) * 40ul) - (first_directory_cache_size * directory_cache_flag);
constexpr uint64_t sec_filter_cache_size = (sec_level_group_num * sizeof(SecCacheEntry));
constexpr uint64_t bot_cache_size = (filter_cache_size - sec_filter_cache_size);
constexpr uint64_t bot_cache_group_num = (bot_cache_size / sizeof(BotCacheEntry));
// 154841 > 32768 ; 超过了第三层，缓存部分第四层
// 增加buc_ptr后：103612 > 32768 ; 超过了第三层，缓存部分第四层

struct FilterCache
{
    SecCacheEntry sec_filter[sec_level_group_num];
    BotCacheEntry bot_filter[bot_cache_group_num];

    bool is_in_cache(uint64_t level, uint64_t group_id);

    void update_epoch(uint64_t level, uint64_t group_id, uint64_t epoch);
    void update_buc_ptr(uint64_t level, uint64_t group_id, uint64_t buc_id, uintptr_t buc_ptr);
    void update_filter(uint64_t level, uint64_t group_id, uint64_t buc_id, uint64_t *filter_data);
    void clear_filter(uint64_t level, uint64_t group_id, uint64_t buc_id);

    uint64_t get_epoch(uint64_t level, uint64_t group_id);
    uintptr_t get_buc_ptr(uint64_t level, uint64_t group_id, uint64_t buc_id);
    uint64_t * get_filter(uint64_t level, uint64_t group_id, uint64_t buc_id);
} __attribute__((aligned(1)));

// Bucket Array连续存放在Directory之后，提前预留好空间
struct Directory
{
    // 当前HashTable层数，从1开始
    uint64_t cur_level;
    TopPointer first_level[init_group_num];
    SecGroupPointer sec_level[init_group_num * fanout];
    InnerGroupPointer bottom_levels[bot_group_num];
    // 为多客户端同步保留的字段，不影响原有空间布局
    uint64_t start_cnt;
    void print(uintptr_t raddr)
    {
        log_err("==Print Dir===");
        log_err("cur_level:%lu", cur_level);
        log_err("first_level:");
        for (auto &e : first_level)
        {
            // e.print();
        }
        log_err("sec_level:");
        for (auto &e : sec_level)
        {
            // e.print();
        }
        uint64_t level = 2;
        uint64_t group_size = sec_level_group_num;
        uint64_t group_cnt = 0;
        uintptr_t ptr_base = raddr + sizeof(uint64_t) + sizeof(TopPointer) * init_group_num +
                             sizeof(SecGroupPointer) * init_group_num * fanout;
        uint64_t target_level = 3;
        uint64_t target_group_id = 486997;
        uint64_t target_range = 0;
        while (level <= cur_level)
        {
            log_err("bottom_levels:%lu ptr_base:%lx", level, ptr_base);
            group_size *= fanout;
            for (uint64_t i = 0; i < group_size; i++)
            {
                if (level == 2 && i == 28245)
                {
                    log_err("bottom_levels:%lu group:%lu group_ptr:%lx ", level, i,
                            ptr_base + i * sizeof(InnerGroupPointer));
                    bottom_levels[group_cnt + i].print();
                }
                if (level == target_level &&
                    ((i >= (target_group_id - target_range)) && (i <= (target_group_id + target_range))))
                {
                    log_err("bottom_levels:%lu group:%lu group_ptr:%lx ", level, i,
                            ptr_base + i * sizeof(InnerGroupPointer));
                    bottom_levels[group_cnt + i].print();
                }
            }
            group_cnt += group_size;
            ptr_base += group_cnt * sizeof(InnerGroupPointer);
            level++;
        }
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

    task<> insert(Slice *key, Slice *value);
    task<bool> search(Slice *key, Slice *value);
    task<> update(Slice *key, Slice *value);
    task<> remove(Slice *key);

  private:
    // 用来在Resize的时候Move数据
    task<> migrate_top(uint64_t group_id, TopPointer *top_group);
    task<> migrate_bot(char *group_pointer, uint64_t source_level, uint64_t group_cnt, uint64_t group_id,
                       uintptr_t group_ptr, uintptr_t buc_start_ptr);
    task<> rehash(Bucket *bucket, uint64_t size, uint64_t level, Slice *keys, Entry *new_entrys, uint64_t *sizes);
    task<> bulk_level_insert(uint64_t level, uint64_t epoch, const Slice *keys, Entry *new_entrys,
                             const uint64_t *sizes);
    Slice *search_keys(Slice *first, Slice *last, Slice &target_key);
    std::tuple<uint64_t, uint64_t, uintptr_t, uintptr_t> cal_group_info(uint64_t next_level);

    task<bool> bot_level_search(uint64_t level, Slice *key, Slice *value, uint64_t pattern);
    task<bool> bot_level_search_wcache(uint64_t level, Slice *key, Slice *value, uint64_t pattern);

    // debug
    task<> print_group(Bucket *buc);
    task<> print_buc(Bucket *buc);
    task<> print_dir();
    task<> print_level();
    task<> print_kv_block(uintptr_t ptr);

    // rdma structs
    rdma_client *cli;
    rdma_conn *conn;
    rdma_conn *wo_wait_conn;
    rdma_rmr seg_rmr;
    struct ibv_mr *lmr;

    Alloc alloc;
    RAlloc ralloc;
    uint64_t machine_id;
    uint64_t cli_id;
    uint64_t coro_id;
    Slice *op_key;
    uint64_t migrate_top_groud_id;
    uint64_t migrate_fanout_id;
    bool print_flag = false;

    // Statistic
    Perf perf;
    uint64_t op_cnt;
    uint64_t miss_cnt;
    uint64_t retry_cnt;
    uint64_t filter_cnt=0;

    // Data part
    DirecotryCache *direcotry_cache;
    FilterCache *filter_cache;
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

} // namespace Plush