#include "plush_single_filter.h"
namespace PlushSingleFilter
{

constexpr uint64_t FIRST_DIRECTORY_OFF = sizeof(uint64_t);
constexpr uint64_t SEC_DIRECTORY_OFF = FIRST_DIRECTORY_OFF + sizeof(TopPointer) * init_group_num;
constexpr uint64_t THIRD_DIRECTORY_OFF = SEC_DIRECTORY_OFF + sizeof(SecGroupPointer) * init_group_num * fanout;

inline __attribute__((always_inline)) uint64_t fp(uint64_t pattern)
{
    return ((uint64_t)((pattern) >> 32) & ((1 << 8) - 1));
}

inline __attribute__((always_inline)) uint64_t get_seg_loc(uint64_t pattern, uint64_t global_depth)
{
    return ((pattern) & ((1 << global_depth) - 1));
}

inline __attribute__((always_inline)) uint64_t get_free_bucket_idx(uint64_t size)
{
    uint64_t free_bucket_idx = size / entry_per_bucket;
    return free_bucket_idx < bucket_per_group ? free_bucket_idx : -1;
}

inline __attribute__((always_inline)) uint64_t get_size_of_last_bucket(uint64_t size)
{
    return size & (entry_per_bucket - 1);
}

inline __attribute__((always_inline)) uint64_t get_size_of_bucket(uint64_t size, uint64_t bucket_idx)
{
    uint64_t first_free_bucket_idx = get_free_bucket_idx(size);

    if (first_free_bucket_idx == -1 || bucket_idx < first_free_bucket_idx)
    {
        return entry_per_bucket;
    }
    else if (bucket_idx == first_free_bucket_idx)
    {
        return get_size_of_last_bucket(size);
    }
    else
    {
        return 0;
    }
}

uint64_t customPow(uint64_t base, uint64_t exponent)
{
    uint64_t result = 1;
    while (exponent > 0)
    {
        result *= base;
        exponent--;
    }
    return result;
}



bool FilterCache::is_in_cache(uint64_t level, uint64_t group_id)
{
    if (level == 1){
        for(uint64_t i = 0 ; i < bucket_per_group ; i++){
            if(bot_filter[group_id].buc_ptr[i]==0) 
                return false;
        }
        return true;
    }
        
    if (level == 2)
        group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
    if (level == 3)
        group_id += sec_level_group_num * fanout * fanout;

    if (group_id >= bot_cache_group_num)
        return false;
    if (level >= 4)
    {
        log_err("level >= 4");
        exit(-1);
        return false;
    }
    for(uint64_t i = 0 ; i < bucket_per_group ; i++){
        if(bot_filter[group_id].buc_ptr[i]==0) return false;
    }
    return true;
}

uint64_t FilterCache::get_epoch(uint64_t level, uint64_t group_id)
{
    if (level == 1)
    {
        return sec_filter[group_id].epoch;
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout * fanout;
        if (group_id >= bot_cache_group_num)
            return UINT64_MAX;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        return bot_filter[group_id].epoch;
    }
}

void FilterCache::update_epoch(uint64_t level, uint64_t group_id, uint64_t epoch)
{
    if (level == 1)
    {
        sec_filter[group_id].epoch = epoch;
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout * fanout;
        if (group_id >= bot_cache_group_num)
            return;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        bot_filter[group_id].epoch = epoch;
    }
}

uintptr_t FilterCache::get_buc_ptr(uint64_t level, uint64_t group_id, uint64_t buc_id)
{
    if (level == 1)
    {
        return sec_filter[group_id].buc_ptr[buc_id];
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout * fanout;
        if (group_id >= bot_cache_group_num)
            return UINT64_MAX;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        return bot_filter[group_id].buc_ptr[buc_id];
    }
}

uint64_t *FilterCache::get_filter(uint64_t level, uint64_t group_id, uint64_t buc_id)
{
    if (level == 1)
    {
        return sec_filter[group_id].filter[buc_id];
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout * fanout;
        if (group_id > bot_cache_group_num)
            return nullptr;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        return bot_filter[group_id].filter[buc_id];
    }
}

void FilterCache::update_buc_ptr(uint64_t level, uint64_t group_id, uint64_t buc_id, uint64_t buc_ptr)
{
    if (level == 1)
    {
        sec_filter[group_id].buc_ptr[buc_id] = buc_ptr;
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout*fanout;
        if (group_id >= bot_cache_group_num)
            return;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        bot_filter[group_id].buc_ptr[buc_id] = buc_ptr;
    }
}

void FilterCache::update_filter(uint64_t level, uint64_t group_id, uint64_t buc_id, uint64_t *filter_data)
{
    if (level == 1)
    {
        sec_filter[group_id].filter[buc_id][0] |= filter_data[0];
        sec_filter[group_id].filter[buc_id][1] |= filter_data[1];
        sec_filter[group_id].filter[buc_id][2] |= filter_data[2];
        sec_filter[group_id].filter[buc_id][3] |= filter_data[3];
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout*fanout;
        if (group_id >= bot_cache_group_num)
            return;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        bot_filter[group_id].filter[buc_id][0] |= filter_data[0];
        bot_filter[group_id].filter[buc_id][1] |= filter_data[1];
    }
}

void FilterCache::clear_filter(uint64_t level, uint64_t group_id, uint64_t buc_id)
{
    if (level == 1)
    {
        memset(&sec_filter[group_id].filter[buc_id][0], 0, sizeof(uint64_t) * 4);
    }
    else
    {
        if (level == 2)
            group_id += sec_level_group_num * fanout; // sec_level实际上是level 1
        if (level == 3)
            group_id += sec_level_group_num * fanout*fanout;
        if (group_id > bot_cache_group_num)
            return;
        if (level >= 4)
        {
            log_err("level >= 4");
            exit(-1);
        }
        memset(&bot_filter[group_id].filter[buc_id][0], 0, sizeof(uint64_t) * 2);
    }
}

Server::Server(Config &config) : dev(nullptr, 1, config.gid_idx), ser(dev)
{
    log_err("config.mem_size:%lu", config.mem_size);
    seg_mr = dev.reg_mr(233, config.mem_size);

    log_err("seg_rmr:addr:%lx len:%lu", (uint64_t)seg_mr->addr, seg_mr->length);
    alloc.Set((char *)seg_mr->addr, seg_mr->length);
    dir = (Directory *)alloc.alloc(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    Init();
    log_err("init");

    // dir->print();

    ser.start_serve();
}

void Server::Init()
{
    dir->cur_level = 0;
    // other parts of top-pointer is zeor

    // no need to zero top buckets
}

Server::~Server()
{
    rdma_free_mr(seg_mr);
}

Client::Client(Config &config, ibv_mr *_lmr, rdma_client *_cli, rdma_conn *_conn, rdma_conn *_wowait_conn,
               uint64_t _machine_id, uint64_t _cli_id, uint64_t _coro_id)
{
    // id info
    machine_id = _machine_id;
    cli_id = _cli_id;
    coro_id = _coro_id;

    // rdma utils
    cli = _cli;
    conn = _conn;
    wo_wait_conn = _wowait_conn;
    lmr = _lmr;

    // alloc info
    alloc.Set((char *)lmr->addr, lmr->length);
    seg_rmr = cli->run(conn->query_remote_mr(233));
    // 对于Cluster Hash，其头部空间全部留着用来作为Table的空间，ralloc仅用来写入KV
    // Block 110000000 * ( 8*2 + 16 + 32) = 6.65 GB
    uint64_t rbuf_size = ((1ul << 30) * 20ul) / (config.num_machine * config.num_cli * config.num_coro);
    uint64_t buf_id = config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id;
    uintptr_t remote_ptr = seg_rmr.raddr + seg_rmr.rlen - rbuf_size * buf_id; // 从尾部开始分配
    ralloc.SetRemote(remote_ptr, rbuf_size, seg_rmr.raddr, seg_rmr.rlen);
    ralloc.alloc(7 * ALIGNED_SIZE, true); // 提前分配ALIGNED_SIZE，免得读取的时候越界
    log_err("ralloc start_addr:%lx offset_max:%lu ", ralloc.raddr, ralloc.rsize);

    // util variable
    op_cnt = 0;
    miss_cnt = 0;

    // sync dir
    filter_cache = (FilterCache *)alloc.alloc(sizeof(FilterCache));
    log_err("init filter_cache");
    memset(&filter_cache->sec_filter[0], 0, sizeof(FilterCache));
    if (cli_id == 0 && coro_id == 0)
    {
        log_err("sizeof(SecGroupPointer):%lu", sizeof(SecGroupPointer));
        log_err("sizeof(InnerGroupPointer):%lu", sizeof(InnerGroupPointer));
    }
}

Client::~Client()
{
    log_err("[%lu:%lu] miss_cnt:%lu filter_cnt:%lu", cli_id, coro_id, miss_cnt,filter_cnt);
}

task<> Client::reset_remote()
{
    // 模拟远端分配器信息
    Alloc server_alloc;
    server_alloc.Set((char *)seg_rmr.raddr, seg_rmr.rlen);
    server_alloc.alloc(sizeof(Directory));

    // 重置远端 Directory
    // Plush Direcotry有200MB，本地借用一下好了
    uint64_t buff_size = (1ul << 20) * 50; // 50MB
    char *buff = alloc.alloc(buff_size);
    memset(buff, 0, buff_size);
    for (uint64_t cnt_size = 0; cnt_size < sizeof(Directory); cnt_size += buff_size)
    {
        co_await conn->write(seg_rmr.raddr + cnt_size, seg_rmr.rkey, buff, buff_size, lmr->lkey);
    }
}

task<> Client::start(uint64_t total)
{
    uint64_t *start_cnt = (uint64_t *)alloc.alloc(sizeof(uint64_t), true);
    *start_cnt = 0;
    co_await conn->fetch_add(seg_rmr.raddr + sizeof(Directory) - sizeof(uint64_t), seg_rmr.rkey, *start_cnt, 1);
    // log_info("Start_cnt:%lu", *start_cnt);
    while ((*start_cnt) < total)
    {
        co_await conn->read(seg_rmr.raddr + sizeof(Directory) - sizeof(uint64_t), seg_rmr.rkey, start_cnt,
                            sizeof(uint64_t), lmr->lkey);
    }
}

task<> Client::stop()
{
    uint64_t *start_cnt = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->fetch_add(seg_rmr.raddr + sizeof(Directory) - sizeof(uint64_t), seg_rmr.rkey, *start_cnt, -1);
    // log_err("Start_cnt:%lu", *start_cnt);
    while ((*start_cnt) != 0)
    {
        co_await conn->read(seg_rmr.raddr + sizeof(Directory) - sizeof(uint64_t), seg_rmr.rkey, start_cnt,
                            sizeof(uint64_t), lmr->lkey);
    }
}

task<> Client::insert(Slice *key, Slice *value)
{
    print_flag = false;
    op_cnt++;
    uint64_t pattern = hash(key->data, key->len);
    uint64_t tmp_fp = fp(pattern);
    KVBlock *kv_block = InitKVBlock(key, value, &alloc);
    uint64_t kvblock_len = key->len + value->len + sizeof(uint64_t) * 2;
    uint64_t kvblock_ptr = ralloc.alloc(kvblock_len);
    this->op_key = key;
    // writekv
    // this->op_key->print(cli_id,coro_id);
    // wo_wait_conn->pure_write(kvblock_ptr, seg_rmr.rkey, kv_block, kvblock_len, lmr->lkey);
    auto write_kv = wo_wait_conn->write(kvblock_ptr, seg_rmr.rkey, kv_block, kvblock_len, lmr->lkey);
    retry_cnt = 0;
Retry:
    retry_cnt++;
    alloc.ReSet(sizeof(FilterCache) + kvblock_len);
    if (retry_cnt > 2)
    {
        // log_err("[%lu:%lu} retry_cnt:%lu", cli_id, coro_id, retry_cnt);
        // this->op_key->print(__LINE__);
    }
    // 1. Cal GroupIdx && BucIdx
    uint64_t group_id = pattern % init_group_num;
    uint64_t buc_id = (pattern / init_group_num) % bucket_per_group;
    // if(group_id==16){
    //     print_flag = true;
    // }

    // 2. Lock mutex of target group
    uintptr_t group_ptr = seg_rmr.raddr + FIRST_DIRECTORY_OFF + sizeof(TopPointer) * group_id;
    if (!co_await conn->cas_n(group_ptr, seg_rmr.rkey, 0, 1))
    {
        // log_err("[%lu:%lu]fail to lock group:%lu at first level", this->cli_id, this->coro_id, group_id);
        // this->op_key->print(cli_id,coro_id,__LINE__);
        goto Retry;
    }

    // 3. Read TopPointer
    TopPointer *top_group = (TopPointer *)alloc.alloc(sizeof(TopPointer));
    co_await conn->read(group_ptr, seg_rmr.rkey, top_group, sizeof(TopPointer), lmr->lkey);

    if (top_group->size[buc_id] >= entry_per_bucket)
    {
        // log_err("[%lu:%lu]migrate_top group:%lu at first level", this->cli_id, this->coro_id, group_id);
        // this->op_key->print(cli_id,coro_id,__LINE__);
        co_await migrate_top(group_id, top_group);
        co_await conn->cas_n(group_ptr, seg_rmr.rkey, 1, 0);
        // uint64_t *lock = (uint64_t *)alloc.alloc(sizeof(uint64_t));
        // lock[0] = 0;
        // co_await conn->write(group_ptr, seg_rmr.rkey, lock, sizeof(uint64_t), lmr->lkey);
        goto Retry;
    }

    // 4. insert to bucket in first level
    uintptr_t entry_ptr = seg_rmr.raddr + sizeof(Directory) + group_id * bucket_per_group * sizeof(Bucket) +
                          buc_id * sizeof(Bucket) + top_group->size[buc_id] * sizeof(Entry);
    Entry *tmp = (Entry *)alloc.alloc(sizeof(Entry));
    tmp->fp = tmp_fp;
    tmp->len = (kvblock_len + ALIGNED_SIZE - 1) / ALIGNED_SIZE;
    tmp->offset = ralloc.offset(kvblock_ptr);
    co_await conn->write(entry_ptr, seg_rmr.rkey, tmp, sizeof(Entry), lmr->lkey);
    co_await std::move(write_kv);

    // 5. fdd size of target bucket
    // 这里直接write也可以？不清楚源代码为啥要用fdd
    co_await conn->fetch_add(group_ptr + (2 + buc_id) * sizeof(uint64_t), seg_rmr.rkey, top_group->size[buc_id], 1);

    // TMP. read bucket to check
    if (*(uint64_t *)key->data == 501)
    {
        // key->print(this->cli_id,this->coro_id);
        // print_flag = true;
        // uint64_t buc_ptr = seg_rmr.raddr + sizeof(Directory) + group_id * bucket_per_group * sizeof(Bucket) + buc_id
        // * sizeof(Bucket); Bucket * buc = (Bucket*)alloc.alloc(sizeof(Bucket)); log_err("pattern:%lx insert into
        // group:%lu buc:%lu entry:%lu buc_ptr:%lx",pattern, group_id, buc_id, top_group->size[buc_id],buc_ptr);
        // co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket), lmr->lkey);
        // co_await print_buc(buc);
        // co_await print_kv_block(kvblock_ptr);
    }

    // 6. unlock target bucket
    co_await conn->cas_n(group_ptr, seg_rmr.rkey, 1, 0);
    // uint64_t *lock = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    // lock[0] = 0;
    // co_await conn->write(group_ptr, seg_rmr.rkey, lock, sizeof(uint64_t), lmr->lkey);
}

task<> Client::migrate_top(uint64_t group_id, TopPointer *top_group)
{
    Entry new_entrys[fanout * entry_per_group];
    Slice keys[fanout * entry_per_group];
    uint64_t sizes[fanout];
    memset(sizes, 0, sizeof(uint64_t) * fanout);
    uint64_t epoch = top_group->epoch;
    this->migrate_top_groud_id = group_id;

    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket) * bucket_per_group);
    // 1. read bucket group; 只有top可以这么做，因为TOP从原理上可以预先分配空间
    uintptr_t buc_ptr = seg_rmr.raddr + sizeof(Directory) + group_id * bucket_per_group * sizeof(Bucket);
    co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket) * bucket_per_group, lmr->lkey);

    // 2. rehash
    for (uint64_t buc_id = 0; buc_id < bucket_per_group; buc_id++)
    {
        co_await rehash(buc + buc_id, top_group->size[buc_id], 0, keys, new_entrys, sizes);
    }

    // 3. insert bucket to next level
    co_await bulk_level_insert(1, epoch, keys, new_entrys, sizes);

    // 4. fetch_add epoch
    uintptr_t group_ptr = seg_rmr.raddr + FIRST_DIRECTORY_OFF + group_id * sizeof(TopPointer);
    co_await conn->fetch_add(group_ptr + sizeof(uint64_t), seg_rmr.rkey, top_group->epoch, 1);

    // 5. clear bucket size of top level at group_id
    for (uint64_t idx = 0; idx < bucket_per_group; ++idx)
    {
        top_group->size[idx] = 0;
    }
    co_await conn->write(group_ptr + 2 * sizeof(uint64_t), seg_rmr.rkey, top_group->size,
                         sizeof(uint64_t) * bucket_per_group, lmr->lkey);
    alloc.free(sizeof(Bucket) * bucket_per_group);
}

Slice *Client::search_keys(Slice *first, Slice *last, Slice &target_key)
{
    for (Slice *cur_key = first; cur_key != last; cur_key++)
    {
        if (cur_key->operator==(target_key))
            return cur_key;
    }
    return last;
}

task<> Client::print_buc(Bucket *buc)
{
    KVBlock *kv_block = (KVBlock *)alloc.alloc(KEY_VALUE_SIZE);
    for (uint64_t entry_id = 0; entry_id < entry_per_bucket; entry_id++)
    {
        if (buc->entrys[entry_id].offset == 0)
            continue;
        buc->entrys[entry_id].print();
        co_await conn->read(ralloc.ptr(buc->entrys[entry_id].offset), seg_rmr.rkey, kv_block,
                            (buc->entrys[entry_id].len) * ALIGNED_SIZE, lmr->lkey);
        kv_block->print();
    }
    alloc.free(KEY_VALUE_SIZE);
}

task<> Client::print_group(Bucket *buc)
{
    for (uint64_t i = 0; i < bucket_per_group; i++)
    {
        log_err("buc:%lu", i);
        co_await print_buc(buc + i);
    }
}

task<> Client::print_dir()
{
    Directory *dir = (Directory *)alloc.alloc(sizeof(Directory));
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, dir, sizeof(Directory), lmr->lkey);
    dir->print(seg_rmr.raddr);
    alloc.free(sizeof(Directory));
}

task<> Client::print_level()
{
    uint64_t *cur_level = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, cur_level, sizeof(uint64_t), lmr->lkey);
    log_err("cur_level:%lu", cur_level[0]);
    alloc.free(sizeof(uint64_t));
}

task<> Client::print_kv_block(uintptr_t ptr)
{
    KVBlock *tmp_block = (KVBlock *)alloc.alloc(KEY_VALUE_SIZE);
    co_await conn->read(ptr, seg_rmr.rkey, tmp_block, KEY_VALUE_SIZE, lmr->lkey);
    log_err("[%lu:%lu]ptr:%lx", cli_id, coro_id, ptr);
    tmp_block->print();
    alloc.free(KEY_VALUE_SIZE);
}

/// @brief 将buc中size大小的entry，根据old_level+1处的1
/// bit追加分配到new_entrys[0]或new_entrys[1]中，并同步填入keys。
/// sizes记录new_entrys[0]和new_entrys[1]的数据量。
/// @param buc
/// @param size
/// @param old_level the level to which the keys belongs,从0(top level)开始
/// @param keys
/// @param new_entrys
/// @param sizes
/// @return
task<> Client::rehash(Bucket *buc, uint64_t size, uint64_t old_level, Slice *keys, Entry *new_entrys, uint64_t *sizes)
{
    uint64_t old_group_id;
    uint64_t new_group_id;
    uint64_t fanout_id;
    uint64_t pattern;
    uint64_t old_group_size = init_group_num * customPow(fanout, old_level);
    uint64_t group_size = old_group_size * fanout;
    Slice tmp_key;
    Slice *pos;

    for (uint64_t key_id = 0; key_id < size; key_id++)
    {
        if (buc->entrys[key_id].offset == 0)
        {
            log_err("[%lu:%lu] empty entry during rehash", this->cli_id, this->coro_id);
            this->op_key->print(this->cli_id, this->coro_id, __LINE__);
            continue;
        }
        // a. read key
        KVBlock *tmp_block = (KVBlock *)alloc.alloc(KEY_VALUE_SIZE);
        co_await conn->read(ralloc.ptr(buc->entrys[key_id].offset), seg_rmr.rkey, tmp_block,
                            (buc->entrys[key_id].len) * ALIGNED_SIZE, lmr->lkey);
        tmp_key.len = tmp_block->k_len;
        tmp_key.data = tmp_block->data;

        // b. cal group id
        pattern = hash(tmp_block->data, tmp_block->k_len);
        new_group_id = pattern % group_size;
        old_group_id = pattern % old_group_size;
        fanout_id = new_group_id / old_group_size;
        // if((*(uint64_t*)tmp_key.data)==9403 || print_flag){
        //     log_err("pattern:%lx old_group_size:%lu group_size:%lu old_group_id:%lu new_group_id:%lu fanout_id:%lu
        //     bucket_size:%lu",pattern, old_group_size, group_size,old_group_id,new_group_id, fanout_id,size);
        //     tmp_key.print(this->cli_id,this->coro_id,__LINE__);
        //     co_await print_buc(buc);
        //     print_flag = true;
        //     this->migrate_fanout_id = fanout_id;
        // }

        // c. remove duplicate key
        Slice *first = keys + (fanout_id * entry_per_group);
        Slice *last = keys + (fanout_id * entry_per_group + sizes[fanout_id]);
        pos = search_keys(first, last, tmp_key);

        if (pos != last)
        {
            uint64_t offset = pos - first;
            new_entrys[fanout_id * entry_per_group + offset] = buc->entrys[key_id];
            continue;
        }

        // d. insert key
        keys[fanout_id * entry_per_group + sizes[fanout_id]] = tmp_key;
        new_entrys[fanout_id * entry_per_group + sizes[fanout_id]] = buc->entrys[key_id];
        ++sizes[fanout_id];
    }
}

/// @brief
/// 计算nextlevel对应的group_size,group_cnt,group_start_ptr和buc_start_ptr;
//          next_level >= 1
/// @return
std::tuple<uint64_t, uint64_t, uintptr_t, uintptr_t> Client::cal_group_info(uint64_t next_level)
{
    uint64_t group_cnt = init_group_num;
    uint64_t group_size = init_group_num * fanout;
    uintptr_t group_start_ptr = seg_rmr.raddr + SEC_DIRECTORY_OFF;
    uintptr_t buc_start_ptr = seg_rmr.raddr + sizeof(Directory) + sizeof(Bucket) * bucket_per_group * init_group_num;
    if (next_level == 1)
    {
        // 目标层次是第二层
        return std::make_tuple(group_size, group_cnt, group_start_ptr, buc_start_ptr);
    }
    // 目标层次是第三层
    group_start_ptr = seg_rmr.raddr + THIRD_DIRECTORY_OFF;
    buc_start_ptr += group_size * sizeof(Bucket) * bucket_per_group;
    group_cnt += group_size;
    group_size *= fanout;
    if (next_level == 2)
    {
        return std::make_tuple(group_size, group_cnt, group_start_ptr, buc_start_ptr);
    }

    // 目标层次高于第三层
    for (uint64_t level_id = 2; level_id < next_level; level_id++)
    {
        group_start_ptr += sizeof(InnerGroupPointer) * group_size;
        buc_start_ptr += sizeof(Bucket) * bucket_per_group * group_size;
        group_cnt += group_size;
        group_size *= fanout;
    }
    return std::make_tuple(group_size, group_cnt, group_start_ptr, buc_start_ptr);
}

/// @brief 将new_entrys写入到next_level中的fanou个group中
/// @param next_level keys将要被写入的层次，从1开始
/// @param epoch
/// @param keys 通过rehash设置的entrys数组，大小为fanout * entry_per_group
/// @param new_entrys 通过rehash设置的entrys数组，大小为fanout * entry_per_group
/// @param sizes uint64 [fanout]数组，记录fanout对应的group中的key数量
/// @return
task<> Client::bulk_level_insert(uint64_t next_level, uint64_t epoch, const Slice *keys, Entry *new_entrys,
                                 const uint64_t *sizes)
{
    // 1. check cur_level
    uint64_t *cur_level = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, cur_level, sizeof(uint64_t), lmr->lkey);
    if (next_level > cur_level[0])
    {
        log_err("[%lu:%lu]fetch_add cur_level to :%lu", this->cli_id, this->coro_id, next_level);
        this->op_key->print(this->cli_id, this->coro_id, __LINE__);
        co_await conn->cas_n(seg_rmr.raddr, seg_rmr.rkey, cur_level[0], next_level);
        // if(next_level>=2)
        // co_await print_dir();
    }

    // 2. Cal Next Level header ptr and buc ptr
    auto [group_size, group_cnt, group_start_ptr, buc_start_ptr] = cal_group_info(next_level);

    // 3. write key to bucket in new level
    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket) * entry_per_group);
    char *group_pointer;
    if (next_level == 1)
    {
        group_pointer = alloc.alloc(sizeof(SecGroupPointer));
        memset(group_pointer, 0, sizeof(SecGroupPointer));
    }
    else
    {
        group_pointer = alloc.alloc(sizeof(InnerGroupPointer));
        memset(group_pointer, 0, sizeof(InnerGroupPointer));
    }
    for (uint64_t fanout_id = 0; fanout_id < fanout; fanout_id++)
    {
        if (next_level == 3)
        {
            // log_err("migrate fanout:%lu with size:%lu",fanout_id,sizes[fanout_id]);
        }

        if (sizes[fanout_id] == 0)
        {
            continue;
        }
        assert(sizes[fanout_id] <= entry_per_group);

        // 3.1 Read Inner Group Pointer
        uint64_t pattern = hash(keys[fanout_id * entry_per_group].data, keys[fanout_id * entry_per_group].len);
        uint64_t group_id = pattern % group_size;
        uint64_t old_group_id = pattern % (group_size / fanout);
        uintptr_t group_ptr = group_start_ptr;

        // 根据层次构造要更新的元数据指针
        uint64_t *entry_in_group;
        uint64_t *epoch_of_group;
        char *bucket_in_group;
        char *buc_ptr_iter;
        uint64_t bucket_pointer_size;
        SecGroupPointer *sec_group_ptr;
        InnerGroupPointer *inner_group_ptr;

        if (next_level == 1)
        {
            group_ptr += group_id * sizeof(SecGroupPointer);
            co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, sizeof(SecGroupPointer), lmr->lkey);
            sec_group_ptr = (SecGroupPointer *)group_pointer;
            entry_in_group = &(sec_group_ptr->size);
            epoch_of_group = &(sec_group_ptr->epoch);
            bucket_in_group = (char *)(sec_group_ptr->bucket_pointers);
            buc_ptr_iter = (char *)&(sec_group_ptr->bucket_pointers[0].buc_ptr);
            bucket_pointer_size = sizeof(SecBucketPointer);
        }
        else
        {
            group_ptr += group_id * sizeof(InnerGroupPointer);
            co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, sizeof(InnerGroupPointer), lmr->lkey);
            inner_group_ptr = (InnerGroupPointer *)group_pointer;
            entry_in_group = &(inner_group_ptr->size);
            epoch_of_group = &(inner_group_ptr->epoch);
            bucket_in_group = (char *)(inner_group_ptr->bucket_pointers);
            buc_ptr_iter = (char *)&(inner_group_ptr->bucket_pointers[0].buc_ptr);
            bucket_pointer_size = sizeof(BucketPointer);
        }

        if (entry_in_group[0] + sizes[fanout_id] > entry_per_group)
        {
            // 3.2 Migrate group at next level to make room for data from top level
            // log_err("[%lu:%lu]Migrate group:%lu at level:%lu to make room", this->cli_id,
            // this->coro_id,group_id,next_level);
            this->migrate_top_groud_id = group_id;
            co_await migrate_bot(group_pointer, next_level, group_cnt, group_id, group_ptr, buc_start_ptr);
        }

        // 3.3 insert entry into free bucket sequentially
        uint64_t elems_inserted = 0;
        uint64_t free_buc_idx = get_free_bucket_idx(entry_in_group[0]);
        uint64_t first_free_buc_idx = free_buc_idx;
        uint64_t first_buc_size = get_size_of_bucket(entry_in_group[0], free_buc_idx);
        uintptr_t first_buc_ptr = buc_start_ptr + (group_id * bucket_per_group + free_buc_idx) * sizeof(Bucket);
        uint64_t buc_cnt = 0;
        memset(buc, 0, sizeof(Bucket) * entry_per_group);
        if (free_buc_idx == -1)
        {
            log_err("No more free buc during migrate");
            exit(-1);
        }

        // 将new_entrys[fanout_id * entry_per_group]开始的sizes[fanout_id]个entry写入到buc之中
        buc_ptr_iter += free_buc_idx * bucket_pointer_size;
        while (free_buc_idx < bucket_per_group && elems_inserted < sizes[fanout_id])
        {
            // a. check bucket ptr
            uintptr_t buc_ptr = buc_start_ptr + (group_id * bucket_per_group + free_buc_idx) * sizeof(Bucket);

            if ((*(uintptr_t *)buc_ptr_iter) == 0)
            {
                (*(uintptr_t *)buc_ptr_iter) = buc_ptr;
                filter_cache->update_buc_ptr(next_level, group_id, free_buc_idx, buc_ptr);
            }
            buc_ptr_iter += bucket_pointer_size;

            // b. calculate free space in bucket
            uint64_t bucket_size = get_size_of_bucket(entry_in_group[0], free_buc_idx);
            uint64_t elems_to_insert = std::min(entry_per_bucket - bucket_size, sizes[fanout_id] - elems_inserted);

            // c. insert entrys
            if (elems_to_insert == 0)
            {
                free_buc_idx++;
                buc_cnt++;
                continue;
            }

            for (uint64_t entry_id = 0; entry_id < elems_to_insert; entry_id++)
            {
                uint64_t tmp_hash = hash(keys[fanout_id * entry_per_group + elems_inserted + entry_id].data,
                                         keys[fanout_id * entry_per_group + elems_inserted + entry_id].len);
                if (next_level == 1)
                {
                    single_hash_filter(tmp_hash,256,sec_group_ptr->bucket_pointers[free_buc_idx].filter);
                    filter_cache->update_filter(next_level, group_id, free_buc_idx, sec_group_ptr->bucket_pointers[free_buc_idx].filter);
                }
                else
                {
                    single_hash_filter(tmp_hash,128,inner_group_ptr->bucket_pointers[free_buc_idx].filter);
                    filter_cache->update_filter(next_level, group_id, free_buc_idx, inner_group_ptr->bucket_pointers[free_buc_idx].filter);
                }

                buc[buc_cnt].entrys[bucket_size + entry_id] =
                    new_entrys[fanout_id * entry_per_group + elems_inserted + entry_id];
            }

            if (print_flag == true && fanout_id == this->migrate_fanout_id)
            {
                log_err("old_group_id:%lu entry_in_group[0]:%lu fanout:%lu group_id:%lu free_buc_idx:%lu "
                        "elems_to_insert:%lu buc_cnt:%lu buc_ptr:%lx ",
                        old_group_id, entry_in_group[0], fanout_id, group_id, free_buc_idx, elems_to_insert, buc_cnt,
                        first_buc_ptr + buc_cnt * sizeof(Bucket));
                co_await print_buc(buc + buc_cnt);
                if (next_level == 1)
                {
                    sec_group_ptr->print();
                }
                else
                {
                    inner_group_ptr->print();
                }
            }

            elems_inserted += elems_to_insert;
            free_buc_idx++;
            buc_cnt++;
        }

        // 3.4 update inner group pointer
        // a. write entries
        co_await conn->write(first_buc_ptr + first_buc_size * sizeof(Entry), seg_rmr.rkey,
                             &(buc[0].entrys[first_buc_size]), elems_inserted * sizeof(Entry), lmr->lkey);
        // // b. write inner group pointer
        if (print_flag == true && fanout_id == this->migrate_fanout_id)
        {
            log_err("level:%lu group_id:%lu group_ptr:%lx", next_level, group_id, group_ptr);
        }
        co_await conn->write(group_ptr + 2 * sizeof(uint64_t) + first_free_buc_idx * bucket_pointer_size, seg_rmr.rkey,
                             bucket_in_group + first_free_buc_idx * bucket_pointer_size, buc_cnt * bucket_pointer_size,
                             lmr->lkey);
        // // c. write inner_group meta(size,epoch)
        entry_in_group[0] += elems_inserted;
        epoch_of_group[0] = epoch;
        filter_cache->update_epoch(next_level, group_id, epoch_of_group[0]);
        co_await conn->write(group_ptr, seg_rmr.rkey, group_pointer, 2 * sizeof(uint64_t), lmr->lkey);

        if (elems_inserted != sizes[fanout_id])
        {
            log_err("[%lu:%lu]left unrehashed data with elems_inserted:%lu sizes[:%lu]=%lu ", this->cli_id,
                    this->coro_id, elems_inserted, fanout_id, sizes[fanout_id]);
            this->op_key->print(this->cli_id, this->coro_id, __LINE__);
            exit(-1);
        }
        assert(elems_inserted == sizes[fanout_id]);
    }
    if (print_flag)
    {
        print_flag = false;
    }
    alloc.free(sizeof(Bucket) * entry_per_group);
}

/// @brief 将source_level中group_id上的数据写入到下一层中对应group上
/// @param source_level 数据所在层次
/// @param group_cnt 从bulk_level_insert中继承的到目标层次之前的group数目
/// @param group_id 在目标层次中要迁移的group
/// @param group_ptr 要迁移group的远端指针
/// @param buc_start_ptr
/// 要迁移group所在level的bucket的起始地址，从bulk_level_insert继承
/// @return
task<> Client::migrate_bot(char *group_pointer, uint64_t source_level, uint64_t group_cnt, uint64_t group_id,
                           uintptr_t group_ptr, uintptr_t buc_start_ptr)
{
    Slice keys[fanout * entry_per_group]; // 每个bucket最多
    Entry entrys[fanout * entry_per_group];
    uint64_t sizes[fanout] = {0};

    // 根据层次构造要更新的元数据指针
    uint64_t *entry_in_group;
    uint64_t *epoch_of_group;
    char *bucket_in_group;
    char *filter_iter;
    uint64_t filter_size;
    uint64_t bucket_pointer_size;
    if (source_level == 1)
    {
        SecGroupPointer *sec_group_ptr = (SecGroupPointer *)group_pointer;
        entry_in_group = &(sec_group_ptr->size);
        epoch_of_group = &(sec_group_ptr->epoch);
        bucket_in_group = (char *)&(sec_group_ptr->bucket_pointers);
        filter_iter = (char *)&(sec_group_ptr->bucket_pointers[0].filter);
        filter_size = 2 * sizeof(__uint128_t);
        bucket_pointer_size = sizeof(SecBucketPointer);
    }
    else
    {
        InnerGroupPointer *inner_group_ptr = (InnerGroupPointer *)group_pointer;
        entry_in_group = &(inner_group_ptr->size);
        epoch_of_group = &(inner_group_ptr->epoch);
        bucket_in_group = (char *)&(inner_group_ptr->bucket_pointers);
        filter_iter = (char *)&(inner_group_ptr->bucket_pointers[0].filter);
        filter_size = sizeof(__uint128_t);
        bucket_pointer_size = sizeof(BucketPointer);
    }

    // log_err("[%lu:%lu]migrate_bot at level:%lu and group:%lu ", this->cli_id, this->coro_id,source_level, group_id);
    // this->op_key->print(__LINE__);

    // 1. rehash && move entrys
    uint64_t rehashed = 0;
    uint64_t buc_idx = 0;
    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket) * bucket_per_group);
    uintptr_t buc_ptr = buc_start_ptr + group_id * bucket_per_group * sizeof(Bucket);
    co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket) * bucket_per_group, lmr->lkey);
    while (rehashed < entry_in_group[0])
    {

        uint64_t to_rehash = std::min(entry_per_bucket, entry_in_group[0] - rehashed);
        co_await rehash(buc + buc_idx, to_rehash, source_level, keys, entrys, sizes);
        // log_err("entry_in_group:%lu rehashed:%lu to_rehash:%lu buc_idx:%lu",
        // entry_in_group[0],rehashed,to_rehash,buc_idx);
        rehashed += to_rehash;
        buc_idx++;
    }
    co_await bulk_level_insert(source_level + 1, epoch_of_group[0], keys, entrys, sizes);

    // 2. zero bloom filter for all buckets at srouce_level - group_id
    for (uint64_t i = 0; i < bucket_per_group; i++)
    {
        memset(filter_iter + i * bucket_pointer_size, 0, filter_size);
        filter_cache->clear_filter(source_level, group_id, i);
    }
    co_await conn->write(group_ptr + 2 * sizeof(uint64_t), seg_rmr.rkey, bucket_in_group,
                         bucket_pointer_size * bucket_per_group, lmr->lkey);

    entry_in_group[0] = 0;
    co_await conn->write(group_ptr, seg_rmr.rkey, entry_in_group, sizeof(uint64_t), lmr->lkey);

    alloc.free(sizeof(Bucket) * bucket_per_group);
}

task<bool> Client::search(Slice *key, Slice *value)
{
    // print_flag = true;
    uint64_t pattern = hash(key->data, key->len);
    uint64_t tmp_fp = fp(pattern);
    this->op_key = key;
Retry:
    alloc.ReSet(sizeof(FilterCache));
    KVBlock *kv_block = (KVBlock *)alloc.alloc(7 * ALIGNED_SIZE);
    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket));

    // 1. Cal GroupIdx && BucIdx
    uint64_t group_id = pattern % init_group_num;
    uint64_t buc_id = (pattern / init_group_num) % bucket_per_group;

    // 2. Read TopPointer
    uintptr_t group_ptr = seg_rmr.raddr + sizeof(uint64_t) + sizeof(TopPointer) * group_id;
    TopPointer *top_group = (TopPointer *)alloc.alloc(sizeof(TopPointer));
    co_await conn->read(group_ptr, seg_rmr.rkey, top_group, sizeof(TopPointer), lmr->lkey);
    uint64_t epoch = top_group->epoch;

    // 3. search in top
    uintptr_t buc_ptr = seg_rmr.raddr + sizeof(Directory) + (group_id * bucket_per_group + buc_id) * sizeof(Bucket);
    co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket), lmr->lkey);
    if (*(uint64_t *)(key->data) % 1000 == 0)
    {
        // this->print_flag = true;
        // this->op_key->print(cli_id,coro_id,__LINE__);
        // co_await print_dir();
        // log_err("find at level 0 group:%lu bucket:%lu",group_id,buc_id);
        // co_await print_buc(buc);
    }

    for (int i = top_group->size[buc_id] - 1; i >= 0; i--)
    {
        if (buc->entrys[i].fp != tmp_fp)
            continue;
        co_await conn->read(ralloc.ptr(buc->entrys[i].offset), seg_rmr.rkey, kv_block,
                            (buc->entrys[i].len) * ALIGNED_SIZE, lmr->lkey);
        if (memcmp(key->data, kv_block->data, key->len) != 0)
            continue;
        co_await conn->read(group_ptr, seg_rmr.rkey, top_group, sizeof(TopPointer), lmr->lkey);
        if (top_group->epoch != epoch)
            goto Retry;
        value->len = kv_block->v_len;
        memcpy(value->data, kv_block->data + kv_block->k_len, value->len);
        co_return true;
    }

    // 4. search in bot
    uint64_t *cur_level = (uint64_t *)alloc.alloc(sizeof(uint64_t));
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, cur_level, sizeof(uint64_t), lmr->lkey);
    uint64_t group_num = sec_level_group_num;
    uint64_t next_level_group_id;
    bool res;
    for (uint64_t level_id = 1; level_id <= cur_level[0]; level_id++)
    {
        next_level_group_id = pattern % group_num;
        if (filter_cache->is_in_cache(level_id, next_level_group_id))
        {
            // this->op_key->print(cli_id,coro_id,__LINE__);
            // log_err("find at level %lu group:%lu bucket:%lu with cache",level_id,group_id,buc_id);
            res = co_await bot_level_search_wcache(level_id, key, value, pattern);
        }
        else
        {
            // this->op_key->print(cli_id,coro_id,__LINE__);
            // log_err("find at level %lu group:%lu bucket:%lu without cache",level_id,group_id,buc_id);
            res = co_await bot_level_search(level_id, key, value, pattern);
        }
        if (res == false)
        {
            group_num *= fanout;
            continue;
        }
        co_return true;
    }

    log_err("[%lu:%lu]No mathc key", this->cli_id, this->coro_id);
    this->op_key->print(this->cli_id, this->coro_id, __LINE__);
    exit(-1);
    co_return false;
}

/// @brief 对于level的group调用is_in_cache判断，只有in cache的group使用这个函数进行search
/// @param level
/// @param key
/// @param value
/// @param pattern
/// @return
task<bool> Client::bot_level_search_wcache(uint64_t level, Slice *key, Slice *value, uint64_t pattern)
{
    auto [group_size, group_cnt, group_start_ptr, buc_start_ptr] = cal_group_info(level);
    uint64_t group_id = pattern % group_size;
    uintptr_t group_ptr;

    // 1. 读取远端size，判断本地cache有效性
    char *group_pointer;
    uint64_t group_pointer_size;
    uint64_t bucket_pointer_size;
    char *filter_iter;
    uint64_t *entry_in_group;
    uint64_t *epoch_of_group;
    char *buc_ptr_iter;
    if (level == 1)
    {
        group_ptr = group_start_ptr + group_id * sizeof(SecGroupPointer);
        group_pointer = (char *)alloc.alloc(sizeof(SecGroupPointer));
        group_pointer_size = sizeof(SecGroupPointer);
        SecGroupPointer *ptr = (SecGroupPointer *)group_pointer;
        filter_iter = (char *)(ptr->bucket_pointers[0].filter);
        entry_in_group = &(ptr->size);
        epoch_of_group = &(ptr->epoch);
        buc_ptr_iter = (char *)&(ptr->bucket_pointers[0].buc_ptr);
        bucket_pointer_size = sizeof(SecBucketPointer);
    }
    else
    {
        group_ptr = group_start_ptr + group_id * sizeof(InnerGroupPointer);
        group_pointer = (char *)alloc.alloc(sizeof(InnerGroupPointer));
        group_pointer_size = sizeof(InnerGroupPointer);
        InnerGroupPointer *ptr = (InnerGroupPointer *)group_pointer;
        filter_iter = (char *)(ptr->bucket_pointers[0].filter);
        entry_in_group = &(ptr->size);
        epoch_of_group = &(ptr->epoch);
        buc_ptr_iter = (char *)&(ptr->bucket_pointers[0].buc_ptr);
        bucket_pointer_size = sizeof(BucketPointer);
    }
Retry:
    memset(group_pointer, 0, group_pointer_size);
    // 1.1 读取远端和本地group size（其实epoch更合适）
    uint64_t cache_epoch = filter_cache->get_epoch(level, group_id);
    co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, 2 * sizeof(uint64_t), lmr->lkey);
    // 1.2 读取远端group_pointer，更新filter和epoch
    if (cache_epoch != epoch_of_group[0])
    {
        log_err("[%lu:%lu]level:%lu group:%lu epoch:%lu not match with cache:%lu", this->cli_id, this->coro_id, level,
                group_id, entry_in_group[0], cache_epoch);
        // a. update epoch
        filter_cache->update_epoch(level, group_id, epoch_of_group[0]);
        // b. update filter
        co_await conn->read(group_ptr + 2 * sizeof(uint64_t), seg_rmr.rkey, group_pointer + 2 * sizeof(uint64_t),
                            group_pointer_size - 2 * sizeof(uint64_t), lmr->lkey);
        char *remote_filter = filter_iter;
        for (uint64_t i = 0; i < bucket_per_group; i++)
        {
            filter_cache->update_buc_ptr(level, group_id, i, *(uint64_t *)buc_ptr_iter);
            filter_cache->update_filter(level, group_id, i, (uint64_t *)remote_filter);
            remote_filter += bucket_pointer_size;
            buc_ptr_iter += bucket_pointer_size;
        }
    }

    // 2. 遍历bucket
    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket));
    uint64_t tmp_fp = fp(pattern);
    for (uint64_t i = 0; i < bucket_per_group; i++)
    {
        // 2.1 计算和比较filter
        uint64_t *cache_filter = filter_cache->get_filter(level, group_id, i);
        bool filter_res;
        if (level == 1)
        {
            uint64_t* cache_filter = filter_cache->get_filter(level, group_id, i);
            filter_res = check_single_hash_filter(pattern,256,cache_filter);
        }
        else
        {
            uint64_t* cache_filter = filter_cache->get_filter(level, group_id, i);
            filter_res = check_single_hash_filter(pattern,128,cache_filter);
        }

        // 2.2 通过filter,读取bucket
        if (!filter_res)
        {
            filter_cnt++;
            continue;
        }

        // 2.3 通过本地cache获取buc_ptr
        uintptr_t buc_ptr = filter_cache->get_buc_ptr(level, group_id, i);
        if(buc_ptr == 0) continue;
        co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket), lmr->lkey);
        // co_await print_buc(buc);

        uint64_t epoch = epoch_of_group[0];
        uint64_t size = entry_in_group[0];
        uint64_t buc_size = get_size_of_bucket(size, i);

        KVBlock *kv_block = (KVBlock *)alloc.alloc(KEY_VALUE_SIZE);
        for (int entry_id = 0; entry_id < buc_size; entry_id++)
        {
            // 比较fp
            if (buc->entrys[entry_id].fp != tmp_fp)
            {
                continue;
            }
            co_await conn->read(ralloc.ptr(buc->entrys[entry_id].offset), seg_rmr.rkey, kv_block,
                                (buc->entrys[entry_id].len) * ALIGNED_SIZE, lmr->lkey);
            // 比较key
            if (memcmp(key->data, kv_block->data, key->len) != 0)
                continue;
            // 重读epoch
            co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, 2 * sizeof(uint64_t), lmr->lkey);
            if (epoch_of_group[0] != epoch)
            {
                log_err("inconsistent remote epoch:%ld local epoch:%lu", epoch_of_group[0], epoch);
                goto Retry;
            }
            value->len = kv_block->v_len;
            memcpy(value->data, kv_block->data + kv_block->k_len, value->len);
            co_return true;
        }
    }
    co_return false;
}

task<bool> Client::bot_level_search(uint64_t level, Slice *key, Slice *value, uint64_t pattern)
{
    auto [group_size, group_cnt, group_start_ptr, buc_start_ptr] = cal_group_info(level);
    uint64_t group_id = pattern % group_size;
    uintptr_t group_ptr;

    char *group_pointer;
    uint64_t group_pointer_size;
    uint64_t bucket_size;
    char *filter_iter;
    uint64_t *entry_in_group;
    uint64_t *epoch_of_group;
    char *buc_ptr_iter;
    if (level == 1)
    {
        group_ptr = group_start_ptr + group_id * sizeof(SecGroupPointer);
        group_pointer = (char *)alloc.alloc(sizeof(SecGroupPointer));
        group_pointer_size = sizeof(SecGroupPointer);
        SecGroupPointer *ptr = (SecGroupPointer *)group_pointer;
        filter_iter = (char *)(ptr->bucket_pointers[0].filter);
        entry_in_group = &(ptr->size);
        epoch_of_group = &(ptr->epoch);
        buc_ptr_iter = (char *)&(ptr->bucket_pointers[0].buc_ptr);
    }
    else
    {
        group_ptr = group_start_ptr + group_id * sizeof(InnerGroupPointer);
        group_pointer = (char *)alloc.alloc(sizeof(InnerGroupPointer));
        group_pointer_size = sizeof(InnerGroupPointer);
        InnerGroupPointer *ptr = (InnerGroupPointer *)group_pointer;
        filter_iter = (char *)(ptr->bucket_pointers[0].filter);
        entry_in_group = &(ptr->size);
        epoch_of_group = &(ptr->epoch);
        buc_ptr_iter = (char *)&(ptr->bucket_pointers[0].buc_ptr);
    }
    memset(group_pointer, 0, group_pointer_size);
Retry:
    // 1. read group pointer
    co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, group_pointer_size, lmr->lkey);

    if (this->print_flag)
    {
        log_err("[%lu:%lu]pattern:%lx find at level:%lu group:%lu group_size:%lu group_ptr:%lx group_start_ptr:%lx "
                "group_pointer_size:%lu",
                this->cli_id, this->coro_id, pattern, level, group_id, group_size, group_ptr, group_start_ptr,
                group_pointer_size);
        if (level == 1)
        {
            SecGroupPointer *ptr = (SecGroupPointer *)group_pointer;
            ptr->print();
        }
        else
        {
            InnerGroupPointer *ptr = (InnerGroupPointer *)group_pointer;
            ptr->print();
        }
    }

    // // 2.iterate overs buckets
    uintptr_t buc_ptr;
    Bucket *buc = (Bucket *)alloc.alloc(sizeof(Bucket));
    uint64_t tmp_fp = fp(pattern);
    for (uint64_t i = 0; i < bucket_per_group; i++)
    {
        // buc_ptr = buc_start_ptr + (group_id * bucket_per_group + i) * sizeof(Bucket);
        buc_ptr = *(uintptr_t *)buc_ptr_iter;
        if (buc_ptr == 0)
        {
            break;
        }
        if (level == 1)
        {
            buc_ptr_iter += sizeof(SecBucketPointer);
        }
        else
        {
            buc_ptr_iter += sizeof(BucketPointer);
        }

        // 2.1 判断filter
        bool filter_res;
        if (level == 1)
        {
            uint64_t *remote_filter = (uint64_t *)filter_iter;
            filter_res = check_single_hash_filter(pattern,256,remote_filter);
            filter_iter += sizeof(SecBucketPointer);
        }
        else
        {
            uint64_t *remote_filter = (uint64_t *)filter_iter;
            filter_res = check_single_hash_filter(pattern,128,remote_filter);
            filter_iter += sizeof(BucketPointer);
        }

        // 2.2 通过filter,读取bucket
        if (!filter_res)
        {
            // log_err("[%lu:%lu]filter failed",this->cli_id,this->coro_id);
            // this->op_key->print(__LINE__);
            // co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket), lmr->lkey);
            // co_await print_buc(buc);
            filter_cnt++;
            continue;
        }

        // log_err("buc_ptr:%lx", buc_ptr);
        co_await conn->read(buc_ptr, seg_rmr.rkey, buc, sizeof(Bucket), lmr->lkey);
        if (print_flag)
        {
            co_await print_buc(buc);
        }

        uint64_t epoch = epoch_of_group[0];
        uint64_t size = entry_in_group[0];
        uint64_t buc_size = get_size_of_bucket(size, i);

        KVBlock *kv_block = (KVBlock *)alloc.alloc(KEY_VALUE_SIZE);
        for (int entry_id = 0; entry_id < buc_size; entry_id++)
        {
            // 比较fp
            if (buc->entrys[entry_id].fp != tmp_fp)
            {
                continue;
            }
            co_await conn->read(ralloc.ptr(buc->entrys[entry_id].offset), seg_rmr.rkey, kv_block,
                                (buc->entrys[entry_id].len) * ALIGNED_SIZE, lmr->lkey);
            // 比较key
            if (memcmp(key->data, kv_block->data, key->len) != 0)
                continue;
            // 重读epoch
            co_await conn->read(group_ptr, seg_rmr.rkey, group_pointer, group_pointer_size, lmr->lkey);
            if (epoch_of_group[0] != epoch)
            {
                log_err("inconsistent remote epoch:%ld local epoch:%lu", epoch_of_group[0], epoch);
                goto Retry;
            }
            value->len = kv_block->v_len;
            memcpy(value->data, kv_block->data + kv_block->k_len, value->len);
            co_return true;
        }
    }
    co_return false;
}

task<> Client::update(Slice *key, Slice *value)
{
    co_await this->insert(key, value);
    co_return;
}
task<> Client::remove(Slice *key)
{
    co_return;
}

} // namespace Plush
