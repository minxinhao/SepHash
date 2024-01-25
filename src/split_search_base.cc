#include "split_search_base.h"
namespace SPLIT_SEARCH_BASE
{

inline __attribute__((always_inline)) uint64_t fp(uint64_t pattern)
{
    return ((uint64_t)((pattern) >> 32) & ((1 << 8) - 1));
}

inline __attribute__((always_inline)) uint64_t fp2(uint64_t pattern)
{
    return ((uint64_t)((pattern) >> 24) & ((1 << 8) - 1));
}

inline __attribute__((always_inline)) uint64_t get_seg_loc(uint64_t pattern, uint64_t global_depth)
{
    return ((pattern) & ((1 << global_depth) - 1));
}

void print_mainseg(Slot *main_seg, uint64_t main_seg_len);

inline __attribute__((always_inline)) std::tuple<uint64_t, uint64_t> get_fp_bit(uint8_t fp1, uint8_t fp2)
{
    uint64_t fp = fp1;
    fp = fp << 8;
    fp = fp | fp2;
    fp = fp & ((1 << 10) - 1);
    uint64_t bit_loc = fp / 64;
    uint64_t bit_info = (fp % 64);
    bit_info = 1ll << bit_info;
    return std::make_tuple(bit_loc, bit_info);
}

void print_bit_map(uint64_t* fp_bitmap){
    for(int i = 0 ; i < 16 ; i++){
        log_err("%16lx",fp_bitmap[i]);
    }
}

Server::Server(Config &config) : dev(nullptr, 1, config.gid_idx), ser(dev)
{
    seg_mr = dev.reg_mr(233, config.mem_size);
    auto [dm, mr] = dev.reg_dmmr(234, dev_mem_size);
    lock_dm = dm;
    lock_mr = mr;

    alloc.Set((char *)seg_mr->addr, seg_mr->length);
    dir = (Directory *)alloc.alloc(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    Init();
    log_err("init");

    // Init locks
    char tmp[dev_mem_size] = {}; // init locks to zero
    lock_dm->memcpy_to_dm(lock_dm, 0, tmp, dev_mem_size);
    log_err("memset");

    ser.start_serve();
}

void Server::Init()
{
    // Set MainTable to zero
    dir->global_depth = INIT_DEPTH;

    // Init CurTable
    CurSeg *cur_seg;
    for (uint64_t i = 0; i < (1 << dir->global_depth); i++)
    {
        dir->segs[i].cur_seg_ptr = (uintptr_t)alloc.alloc(sizeof(CurSeg));
        dir->segs[i].local_depth = INIT_DEPTH;
        cur_seg = (CurSeg *)dir->segs[i].cur_seg_ptr;
        memset(cur_seg, 0, sizeof(CurSeg));
        cur_seg->seg_meta.local_depth = INIT_DEPTH;
        cur_seg->seg_meta.sign = 1;
    }
}

Server::~Server()
{
    rdma_free_mr(seg_mr);
    rdma_free_dmmr({lock_dm, lock_mr});
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
    lock_rmr = cli->run(conn->query_remote_mr(234));
    uint64_t rbuf_size = (seg_rmr.rlen - (1ul << 20) * 20) /
                            (config.num_machine * config.num_cli * config.num_coro); // 头部保留5GB，其他的留给client
    uint64_t buf_id = config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id;
    uintptr_t remote_ptr = seg_rmr.raddr + seg_rmr.rlen - rbuf_size * buf_id; // 从尾部开始分配
    ralloc.SetRemote(remote_ptr, rbuf_size, seg_rmr.raddr, seg_rmr.rlen);
    ralloc.alloc(ALIGNED_SIZE); // 提前分配ALIGNED_SIZE，免得读取的时候越界
    // log_err("ralloc start_addr:%lx offset_max:%lx", ralloc.raddr, ralloc.rsize);

    // util variable
    op_cnt = 0;
    miss_cnt = 0;

    // sync dir
    dir = (Directory *)alloc.alloc(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    memset(offset, 0, sizeof(SlotOffset) * DIR_SIZE);
    for(uint64_t i = 0 ; i < (1<<INIT_DEPTH) ; i++) this->offset[i].sign = 1;
    cli->run(sync_dir());
}

Client::~Client()
{
    // log_err("[%lu:%lu] miss_cnt:%lu", cli_id, coro_id, miss_cnt);
}

task<> Client::cal_utilization(){
    if(this->machine_id !=0 || this->cli_id != 0 || this->coro_id != 0) co_return;
    co_await sync_dir();
    uint64_t space_consumption = sizeof(uint64_t)+(1<<dir->global_depth)*sizeof(DirEntry);
    uint64_t segment_cnt = 0 ;
    uint64_t entry_total = 0 ;
    uint64_t entry_cnt = 0 ;

    // 遍历Segment，统计空间开销和空间利用率
    log_err("global_dep:%lu",dir->global_depth);
    CurSeg * cur_seg = (CurSeg*)alloc.alloc(sizeof(CurSeg));
    for(uint64_t i = 0 ; i < (1<<dir->global_depth) ; i++){
        uint64_t first_index = i & ((1<<dir->segs[i].local_depth)-1);
        first_index |= 1<<dir->segs[i].local_depth ;
        if(dir->segs[i].local_depth == dir->global_depth || i == first_index ){
            space_consumption += sizeof(CurSeg);
            entry_total += SLOT_PER_SEG;
            segment_cnt++;
            
            // add main segment
            co_await conn->read(dir->segs[i].cur_seg_ptr,seg_rmr.rkey,cur_seg,sizeof(CurSeg),lmr->lkey);
            space_consumption += cur_seg->seg_meta.main_seg_len * sizeof(Slot);
            entry_total += cur_seg->seg_meta.main_seg_len;
            entry_cnt += cur_seg->seg_meta.main_seg_len;

            // cal cur segment
            for(uint64_t i = 0 ; i < SLOT_PER_SEG ; i++){
                if(cur_seg->slots[i].sign != cur_seg->seg_meta.sign ){
                    entry_cnt++;
                }
            }
        }
    }
    double space_utilization = (1.0*entry_cnt*sizeof(Slot))/(1.0*space_consumption);
    space_consumption = space_consumption>>20;
    double entry_utilization = (1.0*entry_cnt)/(1.0*entry_total);
    log_err("space_consumption:%luMB segment_cnt:%lu entry_total:%lu entry_cnt:%lu entry_utilization:%lf space_utilization:%lf",space_consumption,segment_cnt,entry_total,entry_cnt,entry_utilization,space_utilization);
}


task<> Client::reset_remote()
{
    // 模拟远端分配器信息
    Alloc server_alloc;
    server_alloc.Set((char *)seg_rmr.raddr, seg_rmr.rlen);
    server_alloc.alloc(sizeof(Directory));

    // 重置远端 Lock
    alloc.ReSet(sizeof(Directory));
    memset(dir, 0, sizeof(Directory));
    co_await conn->write(lock_rmr.raddr, lock_rmr.rkey, dir, dev_mem_size, lmr->lkey);

    // 重置远端segment
    dir->global_depth = INIT_DEPTH;

    CurSeg *cur_seg = (CurSeg *)alloc.alloc(sizeof(CurSeg));
    memset(cur_seg, 0, sizeof(CurSeg));
    cur_seg->seg_meta.local_depth = INIT_DEPTH;
    cur_seg->seg_meta.sign = 1;
    for (uint64_t i = 0; i < (1 << dir->global_depth); i++)
    {
        dir->segs[i].cur_seg_ptr = (uintptr_t)server_alloc.alloc(sizeof(CurSeg));
        dir->segs[i].local_depth = INIT_DEPTH;
        co_await conn->write(dir->segs[i].cur_seg_ptr, seg_rmr.rkey, cur_seg, size_t(sizeof(CurSeg)), lmr->lkey);
    }

    // 重置远端 Directory
    co_await conn->write(seg_rmr.raddr, seg_rmr.rkey, dir, sizeof(Directory), lmr->lkey);
}

task<> Client::start(uint64_t total)
{
    co_await sync_dir();
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

task<> Client::sync_dir()
{
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, &dir->global_depth, 2 * sizeof(uint64_t), lmr->lkey);
    co_await conn->read(seg_rmr.raddr + sizeof(uint64_t), seg_rmr.rkey, dir->segs,
                        (1 << dir->global_depth) * sizeof(DirEntry), lmr->lkey);
    uint64_t dir_size = (1 << dir->global_depth);
    for(uint64_t i = 0 ; i < dir_size ; i++){
        this->offset[i].main_seg_ptr = dir->segs[i].main_seg_ptr;
    }
}

/// @brief 读取远端的Global Depth
/// @return
task<uintptr_t> Client::check_gd(uint64_t segloc = -1)
{
    if(segloc!=-1){
        uintptr_t dentry_ptr = seg_rmr.raddr + sizeof(uint64_t) + segloc*sizeof(DirEntry);
        auto read_cur_ptr = wo_wait_conn->read(dentry_ptr, seg_rmr.rkey, &dir->segs[segloc], 4*sizeof(uint64_t), lmr->lkey);
        co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, &dir->global_depth, sizeof(uint64_t), lmr->lkey);
        co_await read_cur_ptr;
        co_return dir->segs[segloc].cur_seg_ptr;
    }
    co_await conn->read(seg_rmr.raddr, seg_rmr.rkey, &dir->global_depth, sizeof(uint64_t), lmr->lkey);
    co_return 0;    
}

task<> Client::insert(Slice *key, Slice *value)
{
    op_cnt++;
    uint64_t op_size = (1 << 20) * 1;
    // 因为存在pure_write,为上一个操作保留的空间，1MB够用了
    if (op_cnt % 2)
        alloc.ReSet(sizeof(Directory) + op_size);
    else
        alloc.ReSet(sizeof(Directory));
    uint64_t pattern = (uint64_t)hash(key->data, key->len);
    KVBlock *kv_block = InitKVBlock(key, value, &alloc);
    uint64_t kvblock_len = key->len + value->len + sizeof(uint64_t) * 3;
    uint64_t kvblock_ptr = ralloc.alloc(kvblock_len);
    // a. writekv
    wo_wait_conn->pure_write(kvblock_ptr, seg_rmr.rkey, kv_block, kvblock_len, lmr->lkey);
    retry_cnt = 0;
    this->key_num = *(uint64_t *)key->data;
Retry:
    // 1. Cal Segloc according to Global Depth At local
    Slot *tmp = (Slot *)alloc.alloc(sizeof(Slot));
    uint64_t segloc = get_seg_loc(pattern, dir->global_depth);
    uintptr_t segptr = dir->segs[segloc].cur_seg_ptr;
    if(segptr == 0){
        segptr = co_await check_gd(segloc);
        uint64_t new_seg_loc = get_seg_loc(pattern, dir->global_depth);
        if(new_seg_loc != segloc) goto Retry;
    }

    // 2. read segment_meta && segment_slot concurrently
    // a. read meta
    CurSegMeta *seg_meta = (CurSegMeta *)alloc.alloc(sizeof(CurSegMeta));
    auto read_meta = conn->read(segptr + sizeof(uint64_t), seg_rmr.rkey, seg_meta, sizeof(CurSegMeta), lmr->lkey);
    // b. read slots
    Slot *seg_slots = (Slot *)alloc.alloc(sizeof(Slot) * 2 * SLOT_BATCH_SIZE);
    uint64_t seg_offset = this->offset[segloc].offset % SLOT_PER_SEG;
    uintptr_t seg_slots_ptr = segptr + sizeof(uint64_t) + sizeof(CurSegMeta) + seg_offset * sizeof(Slot);
    uint64_t slots_len = SLOT_PER_SEG - seg_offset;
    slots_len = (slots_len < (2 * SLOT_BATCH_SIZE)) ? slots_len : SLOT_BATCH_SIZE;
    auto read_slots = wo_wait_conn->read(seg_slots_ptr, seg_rmr.rkey, seg_slots, sizeof(Slot) * slots_len, lmr->lkey);

    // c. 直接通过main_seg_ptr来判断一致性
    co_await std::move(read_meta);
    if(seg_meta->local_depth > dir->global_depth){
        // 远端segloc上发生了Global SPlit
        // log_err("[%lu:%lu:%lu]remote local_depth:%lu at segloc:%lx exceed local global depth%lu segptr:%lx",cli_id,coro_id,this->key_num,seg_meta->local_depth,segloc,dir->global_depth,segptr);
        if(seg_meta->local_depth <= MAX_DEPTH) dir->global_depth = seg_meta->local_depth;
        uint64_t new_seg_loc = get_seg_loc(pattern, dir->global_depth);
        co_await check_gd(new_seg_loc);
        goto Retry;
    }
    if (seg_meta->main_seg_ptr != this->offset[segloc].main_seg_ptr || seg_meta->sign != this->offset[segloc].sign)
    {
        // 检查一遍Global Depth是否一致
        // TODO:增加segloc参数，读取对应位置的cur_seg_ptr；否则split的信息无法被及时同步
        uintptr_t new_cur_ptr = co_await check_gd(segloc);
        uint64_t new_seg_loc = get_seg_loc(pattern, dir->global_depth);
        if(new_cur_ptr != segptr || segloc != new_seg_loc){
            // log_err("[%lu:%lu:%lu]stale cur_seg_ptr for segloc:%lx with old:%lx new:%lx",cli_id,coro_id,this->key_num,segloc,segptr,new_cur_ptr);
            // log_err("[%lu:%lu:%lu] segloc:%lx edit segoffset:%lu to %lu",cli_id,coro_id,this->key_num,segloc,seg_offset,0lu);
            this->offset[segloc].offset = 0;
            this->offset[segloc].main_seg_ptr = dir->segs[segloc].main_seg_ptr;
            co_await std::move(read_slots);
            goto Retry;
        } 
        // 更新所有指向此Segment的DirEntry
        uint64_t new_local_depth = seg_meta->local_depth;
        uint64_t stride = (1llu) << (dir->global_depth - new_local_depth);
        uint64_t cur_seg_loc;
        uint64_t first_seg_loc = segloc & ((1ull << new_local_depth) - 1);
        for (uint64_t i = 0; i < stride; i++)
        {
            // log_err("[%lu:%lu:%lu] segloc:%lx edit segoffset:%lu to %lu",cli_id,coro_id,this->key_num,cur_seg_loc,seg_offset,0lu);
            cur_seg_loc = (i << new_local_depth) | first_seg_loc;
            dir->segs[segloc].local_depth = seg_meta->local_depth;
            dir->segs[cur_seg_loc].main_seg_ptr = seg_meta->main_seg_ptr;
            dir->segs[cur_seg_loc].main_seg_len = seg_meta->main_seg_len;
            this->offset[cur_seg_loc].sign = seg_meta->sign;
            this->offset[cur_seg_loc].offset = 0;
            this->offset[cur_seg_loc].main_seg_ptr = seg_meta->main_seg_ptr;
        }
        co_await std::move(read_slots);
        // 怎么同步信息；同步哪些信息
        goto Retry;
    }

    // 3. find free slot
    uint64_t sign = !seg_meta->sign;
    uint64_t slot_id = -1;
    co_await std::move(read_slots);

    for (uint64_t i = 0; i < slots_len; i++)
    {
        if (seg_slots[i].sign == sign)
        {
            slot_id = i;
            break;
        }
    }
    if (slot_id == -1)
    {
        // log_err("[%lu:%lu:%lu] segloc:%lx edit segoffset:%lu to %lu",cli_id,coro_id,this->key_num,segloc,seg_offset,(seg_offset+slots_len)%SLOT_PER_SEG);
        this->offset[segloc].offset += slots_len;
        this->offset[segloc].offset = this->offset[segloc].offset%SLOT_PER_SEG;
        goto Retry;
    }
    else if (slot_id == slots_len - 1)
    {
        // log_err("[%lu:%lu:%lu] segloc:%lx edit segoffset:%lu to %lu",cli_id,coro_id,this->key_num,segloc,seg_offset,(seg_offset+slots_len)%SLOT_PER_SEG);
        this->offset[segloc].offset += slots_len;
        this->offset[segloc].offset = this->offset[segloc].offset%SLOT_PER_SEG;
    }

    // 4. write slot
    // a. Init Slot
    uint64_t dep = seg_meta->local_depth - (seg_meta->local_depth % 4); // 按4对齐
    tmp->dep = pattern >> dep;
    tmp->fp = fp(pattern);
    tmp->len = (kvblock_len + ALIGNED_SIZE - 1) / ALIGNED_SIZE;
    tmp->sign = seg_meta->sign;
    tmp->offset = ralloc.offset(kvblock_ptr);

    // b. cas slot
    uintptr_t slot_ptr = seg_slots_ptr + slot_id * sizeof(Slot);
    if (!co_await conn->cas_n(slot_ptr, seg_rmr.rkey,(uint64_t)(seg_slots[slot_id]), *tmp))
    {
        goto Retry;
    }
    // log_err("[%lu:%lu:%lu] segloc:%lx write at segoffset:%lu slot_id:%lu with: main_seg_ptr:%lx seg_meta:sign:%d",cli_id,coro_id,this->key_num,segloc,seg_offset,slot_id,this->offset[segloc].main_seg_ptr,seg_meta->sign);
    
    // 6. write fp2 && bitmap
    // a. write fp2
    tmp->fp_2 = fp2(pattern);
    wo_wait_conn->pure_write(slot_ptr + sizeof(uint64_t), seg_rmr.rkey,
                                &tmp->fp_2, sizeof(uint8_t), lmr->lkey);

    if (seg_offset + slot_id == SLOT_PER_SEG - 1)
    {
        // Split
        co_await Split(segloc, segptr, seg_meta);
        co_return;
    }
    
    // b. write fp bitmap
    auto [bit_loc, bit_info] = get_fp_bit(tmp->fp, tmp->fp_2);
    uintptr_t fp_ptr = segptr + (4 + bit_loc) * sizeof(uint64_t);
    seg_meta->fp_bitmap[bit_loc] = seg_meta->fp_bitmap[bit_loc] | bit_info;
    conn->pure_write(fp_ptr, seg_rmr.rkey,
                                &seg_meta->fp_bitmap[bit_loc], sizeof(uint64_t), lmr->lkey);
}

void Client::merge_insert(Slot *data, uint64_t len, Slot *old_seg, uint64_t old_seg_len, Slot *new_seg)
{
    std::sort(data, data + len);
    uint8_t sign = data[0].sign;
    int off_1 = 0, off_2 = 0;
    for (uint64_t i = 0; i < len + old_seg_len; i++)
    {
        if (data[off_1].sign != sign)
        {
            // log_err("[%lu:%lu:%lu]wrong sign",cli_id,coro_id,this->key_num);
            // print_mainseg(data, len);
            // exit(-1);
        }
        if (data[off_1].fp <= old_seg[off_2].fp)
        {
            new_seg[i] = data[off_1];
            off_1++;
        }
        else
        {
            new_seg[i] = old_seg[off_2];
            off_2++;
        }
        if (off_1 >= len || off_2 >= old_seg_len)
            break;
    }
    if (off_1 < len)
    {
        memcpy(new_seg + old_seg_len + off_1, data + off_1, (len - off_1) * sizeof(Slot));
    }
    else if (off_2 < old_seg_len)
    {
        memcpy(new_seg + len + off_2, old_seg + off_2, (old_seg_len - off_2) * sizeof(Slot));
    }
}

void print_mainseg(Slot *main_seg, uint64_t main_seg_len)
{
    log_err("main_seg_len:%lu", main_seg_len);
    for (uint64_t i = 0; i < main_seg_len; i++)
    {
        main_seg[i].print();
    }
}

void print_fpinfo(FpInfo *fp_info)
{
    for (uint64_t i = 0; i <= UINT8_MAX; i++)
    {
        log_err("FP:%lu NUM:%d", i, fp_info[i].num);
    }
}

void cal_fpinfo(Slot *main_seg, uint64_t main_seg_len, FpInfo *fp_info)
{
    double avg = (1.0 * main_seg_len) / UINT8_MAX;
    uint64_t base_off = 0;
    uint64_t base_index = 0;
    uint64_t predict;
    uint8_t prev_fp = 0;
    uint64_t max_error = 32;
    uint64_t correct_cnt = 0;
    uint64_t err;
    for (uint64_t i = 0; i < main_seg_len; i++)
    {
        fp_info[main_seg[i].fp].num++;
    }
}

task<> Client::Split(uint64_t seg_loc, uintptr_t seg_ptr, CurSegMeta *old_seg_meta)
{
    uint64_t local_depth = old_seg_meta->local_depth;
    uint64_t global_depth = dir->global_depth;
    uint64_t main_seg_ptr = old_seg_meta->main_seg_ptr;
    // 1. Read CurSeg
    CurSeg *cur_seg = (CurSeg *)alloc.alloc(sizeof(CurSeg));
    co_await conn->read(seg_ptr, seg_rmr.rkey, cur_seg, sizeof(CurSeg), lmr->lkey);

    // 因为只有cas写入最后一个slot的cli才会进入到对一个segment的split，所以不用对Segment额外加锁
    if (cur_seg->seg_meta.main_seg_ptr != old_seg_meta->main_seg_ptr || cur_seg->seg_meta.local_depth != local_depth)
    {
        // 不应该发生，直接报错
        log_err("[%lu:%lu:%lu] inconsistent ptr at segloc:%lx local-lp:%lu remote-lp:%lu local-main_ptr:%lx remote-main_ptr:%lx", cli_id, coro_id, this->key_num, seg_loc, local_depth, dir->segs[seg_loc].local_depth, old_seg_meta->main_seg_ptr, dir->segs[seg_loc].main_seg_ptr);
        exit(-1);
    }

    // 2. Read MainSeg
    uint64_t main_seg_size = sizeof(Slot) * dir->segs[seg_loc].main_seg_len;
    MainSeg *main_seg = (MainSeg *)alloc.alloc(main_seg_size);
    co_await conn->read(dir->segs[seg_loc].main_seg_ptr, seg_rmr.rkey, main_seg, main_seg_size, lmr->lkey);

    // 3. Sort Segment
    MainSeg *new_main_seg = (MainSeg *)alloc.alloc(main_seg_size + sizeof(Slot) * SLOT_PER_SEG);
    merge_insert(cur_seg->slots, SLOT_PER_SEG, main_seg->slots, dir->segs[seg_loc].main_seg_len, new_main_seg->slots);
    FpInfo fp_info[MAX_FP_INFO] = {};
    cal_fpinfo(new_main_seg->slots, SLOT_PER_SEG + dir->segs[seg_loc].main_seg_len, fp_info);

    // 4. Split (为了减少协程嵌套层次的开销，这里就不抽象成单独的函数了)
    if (dir->segs[seg_loc].main_seg_len >= MAX_MAIN_SIZE){
        // 为了避免覆盖bug，同时Merge/Local Split中都额外更新了一倍的DirEntry
        // 因此Global Split不用处理DirEntry翻倍操作，只需要更新Global Depth

        // 4.1 Split Main Segment
        MainSeg *new_seg_1 = (MainSeg *)alloc.alloc(main_seg_size + sizeof(Slot) * SLOT_PER_SEG);
        MainSeg *new_seg_2 = (MainSeg *)alloc.alloc(main_seg_size + sizeof(Slot) * SLOT_PER_SEG);
        uint64_t dep_off = (local_depth) % 4;
        bool dep_bit = false;
        uint64_t pattern;
        uint64_t off1 = 0, off2 = 0;
        KVBlock *kv_block = (KVBlock *)alloc.alloc(7 * ALIGNED_SIZE);
        for (uint64_t i = 0; i < (SLOT_PER_SEG + dir->segs[seg_loc].main_seg_len); i++)
        {
            dep_bit = (new_main_seg->slots[i].dep >> dep_off) & 1;
            if (dep_off == 3)
            {
                // if dep_off == 3 (Have consumed all info in dep bits), read && construct new dep
                co_await conn->read(ralloc.ptr(new_main_seg->slots[i].offset), seg_rmr.rkey, kv_block,
                                    new_main_seg->slots[i].len * ALIGNED_SIZE, lmr->lkey);
                pattern = (uint64_t)hash(kv_block->data, kv_block->k_len);
                new_main_seg->slots[i].dep = pattern >> (local_depth + 1);
                if (kv_block->k_len != 8)
                {
                    new_main_seg->slots[i].print();
                    uint64_t cros_seg_loc = get_seg_loc(pattern, local_depth+1);
                    log_err("[%lu:%lu:%lu]kv_block k_len:%lu v_len:%lu key:%lu value:%s cros_seg_loc:%lx",cli_id,coro_id,this->key_num, kv_block->k_len, kv_block->v_len, *(uint64_t *)kv_block->data, kv_block->data + 8, cros_seg_loc);
                    exit(-1);
                }
            }
            if (dep_bit)
                new_seg_2->slots[off2++] = new_main_seg->slots[i];
            else
                new_seg_1->slots[off1++] = new_main_seg->slots[i];
        }
        FpInfo fp_info1[MAX_FP_INFO] = {};
        FpInfo fp_info2[MAX_FP_INFO] = {};
        cal_fpinfo(new_seg_1->slots, off1, fp_info1);
        cal_fpinfo(new_seg_2->slots, off2, fp_info2);

        // 4.2 Update new-main-ptr for DirEntries
        uintptr_t new_cur_ptr = ralloc.alloc(sizeof(CurSeg), true);
        uintptr_t new_main_ptr1 = ralloc.alloc(sizeof(Slot) * off1);
        uintptr_t new_main_ptr2 = ralloc.alloc(sizeof(Slot) * off2);

        // a. 同步远端global depth, 确认split类型
        co_await check_gd();

        // b. update dir
        uint64_t stride = (1llu) << (dir->global_depth - local_depth);
        uint64_t cur_seg_loc;
        uint64_t first_seg_loc = seg_loc & ((1ull << local_depth) - 1);
        uintptr_t cur_seg_ptr ;
        uint64_t dir_size = (1 << dir->global_depth); //为了兼容同步发生的Global Split
        uint64_t dir_bound = 2;
        if(local_depth == dir->global_depth){
            stride = 2; // 为了global split正确触发
            dir_bound = 1;
        }

        for(uint64_t i = 0 ; i < dir_bound ; i++){
            uint64_t offset = i * dir_size;
            for (uint64_t i = 0; i < stride; i++)
            {
                cur_seg_loc = (i << local_depth) | first_seg_loc;
                if (i & 1){
                    // Local SegOffset
                    this->offset[cur_seg_loc+offset].offset = 0;
                    this->offset[cur_seg_loc+offset].main_seg_ptr = new_main_ptr2;
                    // DirEntry
                    dir->segs[cur_seg_loc+offset].cur_seg_ptr = new_cur_ptr;
                    dir->segs[cur_seg_loc+offset].main_seg_ptr = new_main_ptr2;
                    dir->segs[cur_seg_loc+offset].main_seg_len = off2;
                    memcpy(dir->segs[cur_seg_loc+offset].fp, fp_info2, sizeof(FpInfo) * MAX_FP_INFO);
                }else{
                    // Local SegOffset
                    this->offset[cur_seg_loc+offset].offset = 0;
                    this->offset[cur_seg_loc+offset].main_seg_ptr = new_main_ptr1;
                    // DirEntry
                    dir->segs[cur_seg_loc+offset].cur_seg_ptr = seg_ptr;
                    dir->segs[cur_seg_loc+offset].main_seg_ptr = new_main_ptr1;
                    dir->segs[cur_seg_loc+offset].main_seg_len = off1;
                    memcpy(dir->segs[cur_seg_loc+offset].fp, fp_info1, sizeof(FpInfo) * MAX_FP_INFO);
                }
                dir->segs[cur_seg_loc].local_depth = local_depth + 1;
                cur_seg_ptr = seg_rmr.raddr + sizeof(uint64_t) + (cur_seg_loc+offset) * sizeof(DirEntry);
                
                // Update DirEntry
                co_await conn->write(cur_seg_ptr, seg_rmr.rkey,&dir->segs[cur_seg_loc+offset], sizeof(DirEntry), lmr->lkey);

                if (local_depth == dir->global_depth){
                    // global
                    log_err("[%lu:%lu:%lu]Global SPlit At segloc:%lx depth:%lu to :%lu with new seg_ptr:%lx new_main_seg_ptr:%lx", cli_id, coro_id, this->key_num, cur_seg_loc+offset, local_depth, local_depth + 1, i & 1 ? new_cur_ptr:seg_ptr,i & 1 ?new_main_ptr2:new_main_ptr1);
                }else{
                    // local 
                    // log_err("[%lu:%lu:%lu]Local SPlit At segloc:%lx depth:%lu to :%lu with new seg_ptr:%lx new main_seg_ptr:%lx", cli_id, coro_id, this->key_num, cur_seg_loc+offset, local_depth, local_depth + 1, i & 1 ? new_cur_ptr:seg_ptr, i & 1 ? new_main_ptr2:new_main_ptr1);
                }
            }
        }
        // Update Global Depth
        if(local_depth == dir->global_depth){
            dir->global_depth++;
            co_await conn->write(seg_rmr.raddr, seg_rmr.rkey, &dir->global_depth, sizeof(uint64_t), lmr->lkey);
        }
        
        // 4.3 Write New MainSeg to Remote
        // a. New CurSeg && New MainSeg
        CurSeg *new_cur_seg = (CurSeg *)alloc.alloc(sizeof(CurSeg));
        memset(new_cur_seg, 0, sizeof(CurSeg));
        new_cur_seg->seg_meta.local_depth = local_depth + 1;
        new_cur_seg->seg_meta.sign = 1;
        new_cur_seg->seg_meta.main_seg_ptr = new_main_ptr2;
        new_cur_seg->seg_meta.main_seg_len = off2;
        wo_wait_conn->pure_write(new_cur_seg->seg_meta.main_seg_ptr, seg_rmr.rkey, new_seg_2, sizeof(Slot) * off2, lmr->lkey);
        co_await conn->write(new_cur_ptr, seg_rmr.rkey, new_cur_seg, sizeof(CurSeg), lmr->lkey);
        // b. new main_seg for old
        cur_seg->seg_meta.main_seg_ptr = new_main_ptr1;
        cur_seg->seg_meta.main_seg_len = off1;
        cur_seg->seg_meta.local_depth = local_depth + 1;
        // cur_seg->seg_meta.sign = !cur_seg->seg_meta.sign; // 对old cur_seg的清空放到最后?保证同步。
        memset(cur_seg->seg_meta.fp_bitmap, 0, sizeof(uint64_t) * 16);
        wo_wait_conn->pure_write(cur_seg->seg_meta.main_seg_ptr, seg_rmr.rkey, new_seg_1, sizeof(Slot) * off1, lmr->lkey);
        co_await conn->write(seg_ptr + sizeof(uint64_t), seg_rmr.rkey, ((uint64_t *)cur_seg) + 1, sizeof(CurSegMeta),lmr->lkey);


        // 4.4 Change Sign (Equal to unlock this segment)
        cur_seg->seg_meta.sign = !cur_seg->seg_meta.sign;
        co_await wo_wait_conn->write(seg_ptr + sizeof(uint64_t), seg_rmr.rkey, ((uint64_t *)cur_seg) + 1, sizeof(uint64_t),lmr->lkey);
        co_return;
    }

    // 5. Merge
    // 5.1 Write New MainSeg to Remote && Update CurSegMeta
    // a. write main segment
    uintptr_t new_main_ptr = ralloc.alloc(main_seg_size + sizeof(Slot) * SLOT_PER_SEG, true);
    uint64_t new_main_len = dir->segs[seg_loc].main_seg_len + SLOT_PER_SEG;
    wo_wait_conn->pure_write(new_main_ptr, seg_rmr.rkey, new_main_seg->slots,
                                sizeof(Slot) * new_main_len, lmr->lkey);
    // b. Update MainSegPtr/Len and fp_bitmap
    cur_seg->seg_meta.main_seg_ptr = new_main_ptr;
    cur_seg->seg_meta.main_seg_len = main_seg_size / sizeof(Slot) + SLOT_PER_SEG;
    this->offset[seg_loc].offset = 0;
    memset(cur_seg->seg_meta.fp_bitmap, 0, sizeof(uint64_t) * 16);
    co_await conn->write(seg_ptr + 2 * sizeof(uint64_t), seg_rmr.rkey, ((uint64_t *)cur_seg) + 2, sizeof(CurSegMeta) - sizeof(uint64_t),lmr->lkey);

    // 5.2 Update new-main-ptr for DirEntries
    uint64_t stride = (1llu) << (dir->global_depth - local_depth);
    uint64_t cur_seg_loc;
    uint64_t first_seg_loc = seg_loc & ((1ull << local_depth) - 1);
    uintptr_t dentry_ptr ;
    uint64_t dir_size = (1 << dir->global_depth); //为了兼容同步发生的Global Split
    for(uint64_t i = 0 ; i < 2 ; i++){
        uint64_t offset = i * dir_size;
        for (uint64_t i = 0; i < stride; i++)
        {
            cur_seg_loc = (i << local_depth) | first_seg_loc;
            // Local SegOffset
            this->offset[cur_seg_loc+offset].offset = 0;
            this->offset[cur_seg_loc+offset].main_seg_ptr = new_main_ptr;
            // DirEntry
            dir->segs[cur_seg_loc+offset].local_depth = cur_seg->seg_meta.local_depth;
            dir->segs[cur_seg_loc+offset].cur_seg_ptr = seg_ptr;
            dir->segs[cur_seg_loc+offset].main_seg_ptr = new_main_ptr;
            dir->segs[cur_seg_loc+offset].main_seg_len = new_main_len;
            memcpy(dir->segs[cur_seg_loc+offset].fp, fp_info, sizeof(FpInfo) * MAX_FP_INFO);
            dentry_ptr = seg_rmr.raddr + sizeof(uint64_t) + (cur_seg_loc+offset) * sizeof(DirEntry) ;
            // Update
            // 暂时还是co_await吧
            co_await conn->write(dentry_ptr, seg_rmr.rkey,&dir->segs[cur_seg_loc+offset], sizeof(DirEntry) , lmr->lkey);
            // conn->pure_write(dentry_ptr, seg_rmr.rkey,&dir->segs[cur_seg_loc+offset], sizeof(DirEntry), lmr->lkey);
            // log_err("[%lu:%lu:%lu]Merge At segloc:%lx depth:%lu with old_main_ptr:%lx new_main_ptr:%lx",cli_id,coro_id,this->key_num,cur_seg_loc+offset,local_depth,main_seg_ptr,new_main_ptr);
        }
    }
    
    // 5.3 Change Sign (Equal to unlock this segment)
    cur_seg->seg_meta.sign = !cur_seg->seg_meta.sign;
    co_await wo_wait_conn->write(seg_ptr + sizeof(uint64_t), seg_rmr.rkey, ((uint64_t *)cur_seg) + 1, sizeof(uint64_t),lmr->lkey);
}

task<int> Client::LockDir()
{
    // assert((connector.get_remote_addr())%8 == 0);
    if (co_await conn->cas_n(lock_rmr.raddr, lock_rmr.rkey, 0, 1))
    {
        co_return 0;
    }
    int a = 1; // 不知道为啥在33上不加点东西这个函数会卡住
    co_return 1;
}
task<> Client::UnlockDir()
{
    co_await conn->cas_n(lock_rmr.raddr, lock_rmr.rkey, 1, 0);
}

task<std::tuple<uintptr_t, uint64_t>> Client::search(Slice *key, Slice *value)
{
    // 1. Cal Segloc && Pattern
    uint64_t pattern = (uint64_t)hash(key->data, key->len);
    uint64_t pattern_fp1 = fp(pattern);
    uint64_t pattern_fp2 = fp2(pattern);
    auto [bit_loc, bit_info] = get_fp_bit(pattern_fp1,pattern_fp2);
    this->key_num = *(uint64_t *)key->data;
    uintptr_t slot_ptr;
    uint64_t slot_content;
Retry:
    alloc.ReSet(sizeof(Directory));
    uint64_t segloc = get_seg_loc(pattern, dir->global_depth);

    // 2. Get SegPtr, MainSegPtr and Slot Offset
    uintptr_t cur_seg_ptr = dir->segs[segloc].cur_seg_ptr;
    uintptr_t main_seg_ptr = dir->segs[segloc].main_seg_ptr;
    uint64_t main_seg_len = dir->segs[segloc].main_seg_len;
    uint64_t start_pos = 0;
    uint64_t end_pos = main_seg_len;
    uint64_t main_size = (end_pos - start_pos) * sizeof(Slot);

    // 3. Read SegMeta && MainSlots
    CurSeg *cur_seg = (CurSeg *)alloc.alloc(sizeof(CurSeg));
    auto read_cur_seg = conn->read(cur_seg_ptr, seg_rmr.rkey, cur_seg, sizeof(CurSeg)-sizeof(uint64_t), lmr->lkey);
    Slot *main_seg = (Slot *)alloc.alloc(main_size);
    auto read_main_seg = wo_wait_conn->read(main_seg_ptr + start_pos * sizeof(Slot), seg_rmr.rkey, main_seg, main_size, lmr->lkey);
    
    // 4. Check Depth && MainSegPtr
    co_await std::move(read_cur_seg);
    if (cur_seg->seg_meta.main_seg_ptr != this->offset[segloc].main_seg_ptr){
        // 检查一遍Global Depth是否一致
        // TODO:增加segloc参数，读取对应位置的cur_seg_ptr；否则split的信息无法被及时同步
        uintptr_t new_cur_ptr = co_await check_gd(segloc);
        uint64_t new_seg_loc = get_seg_loc(pattern, dir->global_depth);
        if(new_cur_ptr != cur_seg_ptr || segloc != new_seg_loc){
            this->offset[segloc].offset = 0;
            this->offset[segloc].main_seg_ptr = dir->segs[segloc].main_seg_ptr;
            co_await std::move(read_main_seg);
            goto Retry;
        } 
        // 更新所有指向此Segment的DirEntry
        uint64_t new_local_depth = cur_seg->seg_meta.local_depth;
        uint64_t stride = (1llu) << (dir->global_depth - new_local_depth);
        uint64_t cur_seg_loc;
        uint64_t first_seg_loc = segloc & ((1ull << new_local_depth) - 1);
        for (uint64_t i = 0; i < stride; i++)
        {
            cur_seg_loc = (i << new_local_depth) | first_seg_loc;
            dir->segs[cur_seg_loc].main_seg_ptr = cur_seg->seg_meta.main_seg_ptr;
            dir->segs[cur_seg_loc].main_seg_len = cur_seg->seg_meta.main_seg_len;
            this->offset[cur_seg_loc].offset = 0;
            this->offset[cur_seg_loc].main_seg_ptr = cur_seg->seg_meta.main_seg_ptr;
            dir->segs[segloc].local_depth = cur_seg->seg_meta.local_depth;
        }
        co_await std::move(read_main_seg);
        // 怎么同步信息；同步哪些信息
        goto Retry;
    }

    // 5. Find Slot && Read KV
    uint64_t version = UINT64_MAX;
    uint64_t res_slot = UINT64_MAX;
    KVBlock *res = nullptr;
    KVBlock *kv_block = (KVBlock *)alloc.alloc(7 * ALIGNED_SIZE);
    uint64_t dep = dir->segs[segloc].local_depth - (dir->segs[segloc].local_depth % 4); // 按4对齐
    uint8_t dep_info = (pattern >> dep) & 0xf;

    // 5.1 Find In CurSeg
    // 在CurSeg中，相同FP的Slot，更新的Slot会被写入在更靠后的位置
    {
        for (uint64_t i = SLOT_PER_SEG-1; i != -1; i--)
        {
            // curseg_slots[i].print();
            if (cur_seg->slots[i] != 0 && cur_seg->slots[i].fp == pattern_fp1 && cur_seg->slots[i].dep == dep_info && cur_seg->slots[i].fp_2 == pattern_fp2)
            {
                co_await conn->read(ralloc.ptr(cur_seg->slots[i].offset), seg_rmr.rkey, kv_block, (cur_seg->slots[i].len) * ALIGNED_SIZE, lmr->lkey);
                if (memcmp(key->data, kv_block->data, key->len) == 0)
                {
                    slot_ptr = cur_seg_ptr + sizeof(uint64_t) + sizeof(CurSegMeta) +  i * sizeof(Slot);
                    slot_content = cur_seg->slots[i];
                    res_slot = i;
                    res = kv_block;
                    break;
                }
            }
        }
    }

    // 5.2 Find In Main
    // 在Main中，相同FP的Slot，更新的Slot会被写入在更靠前的位置
    co_await std::move(read_main_seg);
    for(uint64_t cnt = 0 ; cnt < 2 ; cnt++){
        for (uint64_t i = 0; i < end_pos - start_pos; i++)
        {
            // main_seg[i].print();
            // 第二遍查找时，不带fp2再查一遍，有可能fp2没写入成功就被merge/split了
            if (main_seg[i] != 0 && main_seg[i].fp == pattern_fp1 && main_seg[i].dep == dep_info)
            {
                if(main_seg[i].fp_2 == pattern_fp2 || cnt == 1){
                    co_await wo_wait_conn->read(ralloc.ptr(main_seg[i].offset), seg_rmr.rkey, kv_block,(main_seg[i].len) * ALIGNED_SIZE, lmr->lkey);
                    if (memcmp(key->data, kv_block->data, key->len) == 0)
                    {
                        slot_ptr = main_seg_ptr + (start_pos + i) * sizeof(Slot);
                        slot_content = main_seg[i];
                        res_slot = i;
                        res = kv_block;
                        break;
                    }
                }
            }
        }
        if(res!=nullptr) break;
    }

    if (res != nullptr && res->v_len != 0)
    {
        value->len = res->v_len;
        memcpy(value->data, res->data + res->k_len, value->len);
        co_return std::make_tuple(slot_ptr, slot_content);;
    }

    co_return std::make_tuple(0ull, 0);
}

// task<> Client::update(Slice *key, Slice *value)
// {
//     co_await this->insert(key,value);
//     co_return;
// }

task<> Client::update(Slice *key, Slice *value)
{
    uint64_t pattern = (uint64_t)hash(key->data, key->len);
    KVBlock *kv_block = InitKVBlock(key, value, &alloc);
    uint64_t kvblock_len = key->len + value->len + sizeof(uint64_t) * 2;
    uint64_t kvblock_ptr = ralloc.alloc(kvblock_len);
    wo_wait_conn->pure_write(kvblock_ptr, seg_rmr.rkey, kv_block, kvblock_len, lmr->lkey);

    char data[1024];
    Slice ret_value;
    ret_value.data = data;
    auto [slot_ptr, old_slot] = co_await search(key, &ret_value);
    
    Slot *tmp = (Slot *)alloc.alloc(sizeof(Slot));
    Slot old = (Slot) old_slot;
    tmp->dep = old.dep;
    tmp->fp = fp(pattern);
    tmp->len = (kvblock_len + ALIGNED_SIZE - 1) / ALIGNED_SIZE;
    tmp->sign = old.sign;
    tmp->offset = ralloc.offset(kvblock_ptr);
    tmp->fp_2 = fp2(pattern);

    if (slot_ptr != 0ull)
    {
        // log_err("[%lu:%lu]slot_ptr:%lx slot:%lx for %lu to be updated with new slot: fp:%d len:%d offset:%lx",cli_id,coro_id,slot_ptr,old_slot,*(uint64_t*)key->data,tmp->fp,tmp->len,tmp->offset);
        // 3rd RTT: Setting the key-value block to full zero
        if (!co_await conn->cas_n(slot_ptr, seg_rmr.rkey, old_slot, *(uint64_t*)tmp)){
            log_err("[%lu:%lu]Fail to update key : %lu",cli_id,coro_id,*(uint64_t*)key->data);
        }
    }else{
        log_err("[%lu:%lu]No match key for %lu to update",cli_id,coro_id,*(uint64_t*)key->data);
    }
    co_return;
}

task<> Client::remove(Slice *key)
{
    co_return;
}

} // namespace SPLIT_OP
