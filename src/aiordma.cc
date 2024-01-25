#include "aiordma.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <ranges>
#include <algorithm>

#ifdef ENABLE_DOCA_DMA
#include <json-c/json.h>
#include <doca_mmap.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#endif

const ibv_qp_cap sr_qp_cap = {
    .max_send_wr = 64,
    .max_recv_wr = 32,
    .max_send_sge = 1,
    .max_recv_sge = 1,
    .max_inline_data = 256,
};

const ibv_qp_cap so_qp_cap = {
    .max_send_wr = 64,
    .max_recv_wr = 0,
    .max_send_sge = 1,
    .max_recv_sge = 1,
    .max_inline_data = 256,
};

const ibv_qp_cap zero_qp_cap = {
    .max_send_wr = 0,
    .max_recv_wr = 0,
    .max_send_sge = 1,
    .max_recv_sge = 1,
    .max_inline_data = 0,
};

struct sock_select_list
{
    int maxfd{0};
    int timeout_us;
    bool dirty{false};
    timeval timeout{.tv_sec = 0, .tv_usec = 0};
    fd_set fds;
    std::vector<int> sks;

    sock_select_list(int _timeout_us) : timeout_us(_timeout_us) {}
    void add(int sk)
    {
        sks.emplace_back(sk);
        if (sk > maxfd)
            maxfd = sk;
    }
    void del(int sk)
    {
        auto psk = std::ranges::find(sks, sk);
        assert_require(psk != sks.end());
        *psk = -1;
        if (maxfd == sk)
            maxfd = *std::ranges::max_element(sks);
        dirty = true;
    }
    void cleanup()
    {
        size_t i = 0, j = 0;
        for (; j < sks.size(); ++i, ++j)
        {
            while (j < sks.size() && sks[j] == -1)
                ++j;
            sks[i] = sks[j];
        }
        for (; i < j; ++i)
            sks.pop_back();
        dirty = false;
    }
    int select()
    {
        if (dirty)
            cleanup();
        timeout.tv_usec = timeout_us;
        FD_ZERO(&fds);
        std::ranges::for_each(sks, [this](int sk)
                              { FD_SET(sk, &fds); });
        int ready_num = ::select(maxfd + 1, &fds, nullptr, nullptr, &timeout);
        assert_require(ready_num >= 0);
        return ready_num;
    }
    constexpr bool isset(int sk) { return FD_ISSET(sk, &fds); }
};

enum
{
    rdma_exchange_proto_invaild,
    rdma_exchange_proto_setup,
    rdma_exchange_proto_ready,
};

struct __rdma_exchange_t
{
    uint16_t proto;
    uint16_t lid;
    uint32_t qp_num;
    uint32_t rkey;
    uint64_t raddr;
    ibv_gid gid;
};

rdma_dev::rdma_dev(const char *dev_name, int _ib_port, int _gid_idx)
    : ib_port(_ib_port), gid_idx(_gid_idx), conn_ids(65536)
{
    ibv_device **dev_list = nullptr;
    ibv_device *ib_dev = nullptr;
    int num_devices = 0;

    dev_list = ibv_get_device_list(&num_devices);
    assert_require(dev_list && num_devices);
    if (!dev_name)
        ib_dev = dev_list[0];
    else
        for (int i = 0; i < num_devices; i++)
            if (!strcmp(ibv_get_device_name(dev_list[i]), dev_name))
            {
                ib_dev = dev_list[i];
                break;
            }
    assert_require(ib_dev);

    assert_require(ib_ctx = ibv_open_device(ib_dev));

    ibv_free_device_list(dev_list);
    dev_list = nullptr;

    if (ibv_query_device(ib_ctx, &device_attr))
    {
        log_warn("failed to query device attributes");
        memset(&device_attr, 0, sizeof(device_attr));
    }
    assert_require(0 == ibv_query_port(ib_ctx, ib_port, &port_attr));

    assert_require(pd = ibv_alloc_pd(ib_ctx));

    assert_require(info_mr = create_mr(rdma_info_mr_size, nullptr, mr_flag_ro));

    auto hdr = (rdma_infomr_hdr *)info_mr->addr;
    hdr->cksum = 0;
    hdr->tail = 0;

    for (int i = 1; i < 65536; ++i)
        conn_ids.enqueue(i);

    log_info("rdma_dev init success");
}

rdma_dev::~rdma_dev()
{
    if (info_mr)
        rdma_free_mr(info_mr, true);
    if (pd && ibv_dealloc_pd(pd))
        log_warn("failed to dealloc pd");
    if (ib_ctx && ibv_close_device(ib_ctx))
        log_warn("failed to close device");
#ifdef ENABLE_DOCA_DMA
    if (dma_dev && doca_dev_close(dma_dev) != DOCA_SUCCESS)
        log_warn("failed to close dma dev");
#endif
    log_info("rdma_dev destory success");
}

ibv_mr *rdma_dev::create_mr(size_t size, void *buf, int mr_flags)
{
    bool malloc_flag = false;
    if (buf == nullptr)
    {
        malloc_flag = true;
        buf = alloc_hugepage(size);
    }
    if (buf == nullptr)
        return nullptr;
    auto mr = ibv_reg_mr(pd, buf, size, mr_flags);
    if (!mr && malloc_flag)
        free_hugepage(buf, upper_align(size, 1 << 21));
    return mr;
}

ibv_mr *rdma_dev::reg_mr(uint32_t mr_id, ibv_mr *mr)
{
    if (!mr)
        return nullptr;
    std::lock_guard _(info_lock);
    auto hdr = (rdma_infomr_hdr *)info_mr->addr;
    if (hdr->tail + sizeof(rdma_rmr) > rdma_info_mr_size || info_idx.contains(mr_id))
        return nullptr;
    auto rmr_info = (rdma_rmr *)(hdr->data + hdr->tail);
    rmr_info->type = rdma_info_type_mr;
    rmr_info->mr_id = mr_id;
    rmr_info->raddr = (uintptr_t)mr->addr;
    rmr_info->rkey = mr->rkey;
    rmr_info->rlen = mr->length;
    hdr->tail += sizeof(rdma_rmr);
    hdr->cksum = crc64(hdr->data, hdr->tail);

    info_idx.emplace(mr_id, mr);
    return mr;
}

ibv_mr *rdma_dev::reg_mr(uint32_t mr_id, size_t size, void *buf, int mr_flags)
{
    ibv_mr *res = create_mr(size, buf, mr_flags);
    if (res && !reg_mr(mr_id, res))
    {
        rdma_free_mr(res, buf == nullptr);
        return nullptr;
    }
    return res;
}

ibv_dm *rdma_dev::create_dm(size_t size, uint32_t log_align)
{
    ibv_alloc_dm_attr dm_attr = {.length = size, .log_align_req = log_align, .comp_mask = 0};
    return ibv_alloc_dm(ib_ctx, &dm_attr);
}

rdma_dmmr rdma_dev::create_dmmr(size_t size, uint32_t log_align, int mr_flags)
{
    ibv_dm *dm = create_dm(size, log_align);
    if (!dm)
        return {};
    ibv_mr *mr = ibv_reg_dm_mr(pd, dm, 0, size, mr_flags | IBV_ACCESS_ZERO_BASED);
    if (!mr)
    {
        ibv_free_dm(dm);
        return {};
    }
    return {dm, mr};
}

rdma_dmmr rdma_dev::reg_dmmr(uint32_t mr_id, size_t size, uint32_t log_align, int mr_flags)
{
    auto [dm, mr] = create_dmmr(size, log_align, mr_flags);
    if (mr && !reg_mr(mr_id, mr))
    {
        rdma_free_dmmr({dm, mr});
        return {};
    }
    return {dm, mr};
}

#ifdef ENABLE_DOCA_DMA
void rdma_dev::enable_dma(const char *dev_name)
{
    assert_require(dma_dev == nullptr);
    uint8_t property_buf[512];
    doca_pci_bdf pci;
    doca_devinfo **devlist;
    doca_devinfo *devinfo{nullptr};
    uint32_t devcount = 0;
    assert_require(doca_devinfo_list_create(&devlist, &devcount) == DOCA_SUCCESS);
    assert_require(devcount);
    if (!dev_name)
        devinfo = *devlist;
    else
    {
        const void *dev_name_raw = dev_name;
        size_t dev_name_len = strlen(dev_name);
        if (dev_name_len == 7 && dev_name[2] == ':' && dev_name[5] == '.')
        {
            uint32_t pci_bus, pci_dev, pci_func;
            auto res = sscanf(dev_name, "%u:%u.%u", &pci_bus, &pci_dev, &pci_func);
            assert_require(res == 3);
            pci.bus = pci_bus;
            pci.device = pci_dev;
            pci.function = pci_func;
            dev_name_raw = &pci;
            dev_name_len = sizeof(doca_pci_bdf);
        }
        for (uint32_t i = 0; !devinfo && i < devcount; ++i)
            for (auto [property, len] : std::initializer_list<std::tuple<doca_devinfo_property, uint32_t>>{
                     {DOCA_DEVINFO_PROPERTY_PCI_ADDR, sizeof(doca_pci_bdf)},
                     {DOCA_DEVINFO_PROPERTY_IFACE_NAME, 256},
                     {DOCA_DEVINFO_PROPERTY_IBDEV_NAME, 64},
                 })
                if (doca_devinfo_property_get(devlist[i], property, property_buf, len) == DOCA_SUCCESS && memcmp(dev_name_raw, property_buf, dev_name_len) == 0)
                {
                    devinfo = devlist[i];
                    break;
                }
    }
    assert_require(devinfo);
    assert_require(doca_dev_open(devinfo, &dma_dev) == DOCA_SUCCESS);
    assert_require(doca_devinfo_list_destroy(devlist) == DOCA_SUCCESS);
}

std::tuple<doca_mmap *, void *> rdma_dev::create_mmap(uint32_t mmap_id, size_t len, void *addr)
{
    bool alloc_flag = false;
    doca_mmap *mmp = nullptr;
    assert_require(doca_mmap_create(std::to_string(mmap_id).c_str(), &mmp) == DOCA_SUCCESS);
    assert_require(doca_mmap_start(mmp) == DOCA_SUCCESS);
    assert_require(doca_mmap_dev_add(mmp, dma_dev) == DOCA_SUCCESS);
    assert_require(addr != nullptr || (alloc_flag = (addr = alloc_hugepage(len)) != nullptr));
    assert_require(doca_mmap_populate(mmp, (char *)addr, len, 1 << 21, alloc_flag ? free_mmap_mem : nullptr, nullptr) == DOCA_SUCCESS);
    return {mmp, addr};
}

std::tuple<doca_mmap *, void *> rdma_dev::reg_mmap(uint32_t mmap_id, std::tuple<doca_mmap *, void *> &mmpaddr)
{
    void *export_desc;
    size_t export_desc_len;
    auto [mmp, addr] = mmpaddr;
    if (!mmp)
        return {nullptr, nullptr};
    assert_require(doca_mmap_export(mmp, dma_dev, &export_desc, &export_desc_len) == DOCA_SUCCESS);
    std::lock_guard _(info_lock);
    auto hdr = (rdma_infomr_hdr *)info_mr->addr;
    if (hdr->tail + sizeof(rdma_rmmap) + export_desc_len > rdma_info_mr_size || info_idx.contains(mmap_id))
    {
        free(export_desc);
        return {nullptr, nullptr};
    }
    auto rmmap_info = (rdma_rmmap *)(hdr->data + hdr->tail);
    rmmap_info->type = rdma_info_type_mmap;
    rmmap_info->mmap_id = mmap_id;
    rmmap_info->len = export_desc_len;
    memcpy(rmmap_info->data, export_desc, export_desc_len);
    free(export_desc);
    hdr->tail += sizeof(rdma_rmmap) + export_desc_len;
    hdr->cksum = crc64(hdr->data, hdr->tail);
    info_idx.emplace(mmap_id, mmp);
    return mmpaddr;
}

std::tuple<doca_mmap *, void *> rdma_dev::reg_mmap(uint32_t mmap_id, size_t len, void *addr)
{
    auto mmpaddr = create_mmap(mmap_id, len, addr);
    if (std::get<0>(mmpaddr) && !std::get<0>(reg_mmap(mmap_id, mmpaddr)))
    {
        free_mmap(std::get<0>(mmpaddr));
        return {nullptr, nullptr};
    }
    return mmpaddr;
}
#endif

rdma_worker::rdma_worker(rdma_dev &_dev, const ibv_qp_cap &_qp_cap, int tempmp_size, int _max_coros, int cq_size)
    : dev(_dev), qp_cap(_qp_cap), max_coros(_max_coros)
{
    if (qp_cap.max_send_wr == 0 && qp_cap.max_recv_wr == 0)
    {
        assert_require(cq = dev.create_cq(1));
        return;
    }
    if (tempmp_size > 0)
    {
        assert_require(mp = new tempmp(tempmp_size));
        assert_require(mpmr = dev.create_mr(mp->get_data_len(), mp->get_data_addr()));
    }
    if (max_coros > 8)
    {
        assert_require(max_coros < rdma_coro_none);
        coros = new rdma_coro[max_coros];
        assert_require(coros && is_times_ofN((uintptr_t)coros, sizeof(rdma_coro)));
        free_head = 0;
        coros[0].id = 0;
        for (int i = 1; i < max_coros; ++i)
        {
            coros[i].id = i;
            coros[i - 1].next = i;
        }
        coros[max_coros - 1].next = rdma_coro_none;
    }
    assert_require(cq = dev.create_cq(cq_size));
    if (qp_cap.max_recv_wr > 0)
        assert_require(pending_tasks = new task_ring());
    assert_require(yield_handler = new handle_ring(max_coros));
}

rdma_worker::~rdma_worker()
{
    if (cq && ibv_destroy_cq(cq))
        log_warn("failed to destory cq");
    if (mpmr)
        rdma_free_mr(mpmr, false);
    if (mp)
        delete mp;
    if (coros)
        delete[] coros;
    if (pending_tasks)
        delete pending_tasks;
    if (yield_handler)
        delete yield_handler;
#ifdef ENABLE_DOCA_DMA
    if (mpmmp && doca_mmap_destroy(mpmmp) != DOCA_SUCCESS)
        log_warn("failed to destroy tempmp mmap");
    if (dma_workq && doca_ctx_workq_rm(dma_ctx, dma_workq) != DOCA_SUCCESS)
        log_warn("failed to rm dma workq from ctx");
    if (dma_ctx && doca_ctx_stop(dma_ctx) != DOCA_SUCCESS)
        log_warn("failed to stop dma ctx");
    if (dma_ctx && doca_ctx_dev_rm(dma_ctx, dev.dma_dev) != DOCA_SUCCESS)
        log_warn("failed to rm ctx from dev");
    if (dma_workq && doca_workq_destroy(dma_workq) != DOCA_SUCCESS)
        log_warn("failed to destroy workq");
    if (dma && doca_dma_destroy(dma) != DOCA_SUCCESS)
        log_warn("failed to destroy dma");
    if (buf_inv && doca_buf_inventory_destroy(buf_inv) != DOCA_SUCCESS)
        log_warn("failed to destroy buf_inv");
    if (pending_dma_task)
        delete pending_dma_task;
#endif
}

rdma_coro *rdma_worker::alloc_coro(uint16_t conn_id)
{
    if (free_head == rdma_coro_none)
        return nullptr;
    auto local_head = free_head;
    rdma_coro *res = coros + local_head;
#ifdef ALLOC_CORO_THREAD_SAFE
    while (!__atomic_compare_exchange_n(&free_head, &local_head, res->next, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
        res = coros + local_head;
#else
    free_head = res->next;
#endif
    res->next = rdma_coro_none;
    res->coro_state = coro_state_invaild;
    res->resume_handler = nullptr;
    res->ctx = conn_id;
    return res;
}

void rdma_worker::free_coro(rdma_coro *cor)
{
    cor->ctx = 0;
    cor->next = free_head;
#ifdef ALLOC_CORO_THREAD_SAFE
    while (!__atomic_compare_exchange_n(&free_head, &cor->next, cor->id, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
        ;
#else
    free_head = cor->id;
#endif
}

task<> rdma_worker::cancel_coros(uint16_t conn_id, std::vector<int> &&cancel_list, volatile int &finish_flag)
{
    for (auto e : cancel_list)
        if (auto &&cor = coros[e]; cor.ctx == conn_id)
        {
            cor.coro_state |= (coro_state_error | coro_state_ready);
            if (cor.coro_state & coro_state_inited)
                cor.resume_handler();
        }
    finish_flag = 1;
    co_return;
}

void rdma_worker::worker_loop()
{
    ibv_wc wcs[rdma_max_wc_per_poll];
    int ready_num;
    loop_flag = true;
#ifdef ENABLE_DOCA_DMA
    struct doca_event event = {0};
    doca_error_t dma_workq_res;
#endif
    while (loop_flag)
    {
        assert_require((ready_num = ibv_poll_cq(cq, rdma_max_wc_per_poll, wcs)) >= 0);
        for (int i = 0; i < ready_num; ++i)
        {
            auto &&wc = wcs[i];
            log_debug("polled %lu", wc.wr_id);

            if(wc.wr_id == wr_wo_await){
                if (wc.status != IBV_WC_SUCCESS)
                {
                    log_warn("got bad completion with status: 0x%x, vendor syndrome: 0x%x", wc.status, wc.vendor_err);
                }
                continue;
            }

            auto cor = coros + wc.wr_id;
            if (wc.status != IBV_WC_SUCCESS)
            {
                log_warn("got bad completion with status: 0x%x, vendor syndrome: 0x%x", wc.status, wc.vendor_err);
                cor->coro_state |= coro_state_error;
            }
            if (cor->coro_state & coro_state_inited)
            {
                log_debug("imm resume");
                cor->resume_handler();
            }
            else
            {
                log_debug("wait for resume");
                cor->coro_state |= coro_state_ready;
            }
        }
        if (pending_tasks && pending_tasks->count())
            pending_tasks->dequeue().start([](auto &&) {});
        if (yield_handler && yield_handler->count())
            yield_handler->dequeue()();
#ifdef ENABLE_DOCA_DMA
        if (dma_workq && (dma_workq_res = doca_workq_progress_retrieve(dma_workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) != DOCA_ERROR_AGAIN)
        {
            assert_require(dma_workq_res == DOCA_SUCCESS && event.result.u64 == DOCA_SUCCESS); // TODO: state as future result
            pending_dma_task->dequeue()();
        }
#endif
    }
}

#ifdef ENABLE_DOCA_DMA
void rdma_worker::enable_dma(uint32_t workq_size, size_t buf_inv_size)
{
    assert_require(buf_inv == nullptr && dma == nullptr && dma_ctx == nullptr && dma_workq == nullptr);
    assert_require(doca_buf_inventory_create("buf_inventory", buf_inv_size, DOCA_BUF_EXTENSION_NONE, &buf_inv) == DOCA_SUCCESS);
    assert_require(doca_dma_create(&dma) == DOCA_SUCCESS);
    assert_require(dma_ctx = doca_dma_as_ctx(dma));
    assert_require(doca_workq_create(workq_size, &dma_workq) == DOCA_SUCCESS);
    assert_require(doca_buf_inventory_start(buf_inv) == DOCA_SUCCESS);
    assert_require(doca_ctx_dev_add(dma_ctx, dev.dma_dev) == DOCA_SUCCESS);
    assert_require(doca_ctx_start(dma_ctx) == DOCA_SUCCESS);
    assert_require(doca_ctx_workq_add(dma_ctx, dma_workq) == DOCA_SUCCESS);
    if (mp)
    {
        std::tie(mpmmp, std::ignore) = dev.create_mmap(dma_tempmp_mmap_name, mp->get_data_len(), mp->get_data_addr());
        assert_require(mpmmp);
    }
    assert_require(pending_dma_task = new handle_ring(workq_size));
}
#endif

rdma_server::~rdma_server()
{
    stop_serve();
}

void rdma_server::start_serve(std::function<task<>(rdma_conn*)> handler, int worker_num, const ibv_qp_cap &qp_cap,
                              int tempmp_size, int max_coros, int cq_size, int port)
{
    sockaddr_in local_addr;
    assert_require((listenfd = socket(AF_INET, SOCK_STREAM, 0)) != -1);

    // set socket reuse and nonblock
    {
        int optval = 1;
        assert_require(0 == setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)));

        int sflag;
        assert_require((sflag = fcntl(listenfd, F_GETFL, 0)) != -1 && fcntl(listenfd, F_SETFL, sflag | O_NONBLOCK) != -1);
    }

    bzero(&local_addr, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    assert_require(::bind(listenfd, (sockaddr *)&local_addr, sizeof(sockaddr)) != -1);
    assert_require(::listen(listenfd, 5) != -1);

    if (handler)
    {
        assert_require(worker_num >= 1);
        for (int i = 0; i < worker_num; ++i)
        {
            assert_require(workers.emplace_back(new rdma_worker(dev, qp_cap.max_send_wr == 0 && qp_cap.max_recv_wr == 0 ? sr_qp_cap : qp_cap, tempmp_size, max_coros, cq_size)));
            worker_threads.emplace_back(std::thread(&rdma_worker::worker_loop, workers[i]));
        }
    }
    else
    {
        assert_require(worker_num == 1);
        assert_require(qp_cap.max_send_wr == 0 && qp_cap.max_recv_wr == 0);
        workers.emplace_back(new rdma_worker(dev, qp_cap, 0, 0, 1)); // cq only
        worker_threads.emplace_back(std::thread());
    }

    auto ser_loop = [this, handler, worker_num](const std::stop_token &st)
    {
        uint8_t recv_buf[rdma_sock_recv_buf_size];
        sock_select_list select_list(100);
        socklen_t addr_len = 0;
        sockaddr_in remote_addr;

        select_list.add(listenfd);
        while (!st.stop_requested())
        {
            if (select_list.select())
            {
                auto &sks = select_list.sks;
                size_t sk_num = sks.size();
                for (size_t i = 0; i < sk_num; ++i)
                {
                    int sk = sks[i];
                    if (!select_list.isset(sk))
                        continue;
                    if (sk == listenfd)
                    {
                        int accepted_sock = ::accept(listenfd, (sockaddr *)&remote_addr, &addr_len);
                        assert_require(accepted_sock > 0);
                        select_list.add(accepted_sock);
                        log_info("accept conn: %d", accepted_sock);
                        auto worker = workers[accepted_sock % worker_num];
                        auto conn = new rdma_conn(worker, accepted_sock);
                        assert_require(conn);
                        sk2conn[accepted_sock] = conn;
                    }
                    else
                    {
                        auto conn = sk2conn[sk];
                        log_info("sock event");
                        auto recv_len = ::recv(sk, recv_buf, rdma_sock_recv_buf_size, 0);
                        if (recv_len <= 0)
                        {
                            delete conn;
                            sk2conn.erase(sk);
                            close(sk);
                            select_list.del(sk);
                            log_info("connection closed: %d", sk);
                        }
                        else
                        {
                            switch (((__rdma_exchange_t *)recv_buf)->proto)
                            {
                            case rdma_exchange_proto_setup:
                                conn->handle_recv_setup(recv_buf, recv_len);
                                break;
                            case rdma_exchange_proto_ready:
                                if (handler)
                                    workers[sk % worker_num]->pending_tasks->enqueue(handler(conn));
                                break;

                            default:
                                break;
                            }
                        }
                    }
                }
            }
        }
    };
    sock_thread = std::jthread(ser_loop);
}

void rdma_server::stop_serve()
{
    sock_thread.request_stop();
    for (size_t i = 0; i < workers.size(); ++i)
    {
        workers[i]->loop_flag = false;
        if (worker_threads[i].joinable())
            worker_threads[i].join();
        delete workers[i];
    }
    worker_threads.clear();
    workers.clear();
    sk2conn.clear();
    sock_thread = std::jthread();
    if (listenfd != -1)
        close(listenfd);
    listenfd = -1;
}

rdma_conn *rdma_worker::connect(const char *host, int port)
{
    uint8_t recv_buf[rdma_sock_recv_buf_size];
    int sock;
    sockaddr_in remote_addr;
    assert_require(-1 != (sock = socket(AF_INET, SOCK_STREAM, 0)));
    bzero(&remote_addr, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(port);
    remote_addr.sin_addr.s_addr = inet_addr(host);
    assert_require(-1 != ::connect(sock, (sockaddr *)&remote_addr, sizeof(sockaddr)));
    log_info("socket connected");

    auto conn = new rdma_conn(this, sock);
    if (!conn)
        log_err("failed to alloc conn");
    size_t recv_len = 0;
    while ((recv_len += recv(sock, recv_buf + recv_len, rdma_sock_recv_buf_size - recv_len, 0)) < sizeof(__rdma_exchange_t))
        ;
    log_info("RTR -> RTS");
    conn->handle_recv_setup(recv_buf, recv_len);
    recv_len = 0;
    while ((recv_len += recv(sock, recv_buf + recv_len, rdma_sock_recv_buf_size - recv_len, 0)) < sizeof(uint16_t))
        ;

    log_info("connect success");
    return conn;
}

rdma_conn::rdma_conn(rdma_worker *w, int _sock)
    : dev(w->dev), worker(w), sock(_sock), conn_id(dev.alloc_conn_id())
{
    {
        struct ibv_qp_init_attr qp_init_attr;
        memset(&qp_init_attr, 0, sizeof(qp_init_attr));
        qp_init_attr.qp_type = IBV_QPT_RC;
        qp_init_attr.sq_sig_all = 0;
        qp_init_attr.send_cq = worker->cq;
        qp_init_attr.recv_cq = worker->cq;
        qp_init_attr.cap = worker->qp_cap;
        assert_require(qp = ibv_create_qp(dev.pd, &qp_init_attr));
    }

    assert_require(exchange_mr = dev.create_mr(rdma_info_mr_size, nullptr, mr_flag_lo));

    auto hdr = (rdma_infomr_hdr *)exchange_mr->addr;
    hdr->tail = 0;

    send_exchange(rdma_exchange_proto_setup);
    log_info("new conn %d", sock);
}

rdma_conn::~rdma_conn()
{
    if (sock != -1)
        close(sock);
    if (qp && ibv_destroy_qp(qp))
        log_warn("failed to destroy qp");
    if (exchange_mr)
        rdma_free_mr(exchange_mr);
    release_working_coros();
    dev.free_conn_id(conn_id);
    log_info("close conn %d  %u", sock, conn_id);
}

void rdma_conn::release_working_coros()
{
    if (!worker || !worker->coros || !worker->pending_tasks)
        return;
    std::vector<int> cancel_list;
    for (int i = 0; i < worker->max_coros; ++i)
        if (worker->coros[i].ctx == conn_id)
            cancel_list.push_back(i);
    volatile int finish_flag = 0;
    if (worker->loop_flag) // WARNING: should not close conn during stopping work loop
        worker->pending_tasks->enqueue(worker->cancel_coros(conn_id, std::move(cancel_list), finish_flag));
    else
        worker->run(worker->cancel_coros(conn_id, std::move(cancel_list), finish_flag));
    while (finish_flag == 0)
        ;
}

void rdma_conn::send_exchange(uint16_t proto)
{
    __rdma_exchange_t exc;
    union ibv_gid local_gid;
    exc.proto = proto;
    if (proto == rdma_exchange_proto_setup)
    {
        if (dev.gid_idx >= 0)
        {
            assert_require(0 == ibv_query_gid(dev.ib_ctx, dev.ib_port, dev.gid_idx, &local_gid));
            memcpy(&exc.gid, &local_gid, sizeof(exc.gid));
        }
        else
            memset(&exc.gid, 0, sizeof(exc.gid));
        exc.lid = dev.port_attr.lid;
        exc.qp_num = qp->qp_num;
        exc.raddr = (uint64_t)dev.info_mr->addr;
        exc.rkey = dev.info_mr->rkey;
        assert_require(::send(sock, &exc, sizeof(__rdma_exchange_t), 0) == sizeof(__rdma_exchange_t));
    }
    else if (proto == rdma_exchange_proto_ready)
    {
        assert_require(::send(sock, &exc, sizeof(uint16_t), 0) == sizeof(uint16_t));
    }
    else
        assert_require(0);
}

void rdma_conn::handle_recv_setup(const void *buf, size_t len)
{
    auto exc = (const __rdma_exchange_t *)buf;
    memset(exchange_wr, 0, sizeof(ibv_send_wr));
    __exchange_sge.addr = (uint64_t)exchange_mr->addr;
    __exchange_sge.length = 0;
    __exchange_sge.lkey = exchange_mr->lkey;
    exchange_wr->sg_list = &__exchange_sge;
    exchange_wr->num_sge = 1;
    exchange_wr->opcode = IBV_WR_RDMA_READ;
    exchange_wr->wr.rdma.remote_addr = exc->raddr;
    exchange_wr->wr.rdma.rkey = exc->rkey;

    assert_require(!(modify_qp_to_init() ||
              modify_qp_to_rtr(exc->qp_num, exc->lid, &exc->gid) ||
              (worker->coros && modify_qp_to_rts())));

    send_exchange(rdma_exchange_proto_ready);
}

int rdma_conn::modify_qp_to_init()
{
    const int flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = dev.ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC;
    if ((rc = ibv_modify_qp(qp, &attr, flags)))
        log_err("failed to modify QP state to INIT");
    return rc;
}

int rdma_conn::modify_qp_to_rtr(uint32_t rqp_num, uint16_t rlid, const ibv_gid *rgid)
{
    const int flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                      IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    // attr.path_mtu = IBV_MTU_256;
    // attr.path_mtu = IBV_MTU_512;
    attr.path_mtu = IBV_MTU_1024;
    attr.dest_qp_num = rqp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = rdma_max_rd_atomic;
    attr.min_rnr_timer = 12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = rlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = dev.ib_port;
    if (dev.gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        memcpy(&attr.ah_attr.grh.dgid, rgid, sizeof(ibv_gid));
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 1;
        attr.ah_attr.grh.sgid_index = dev.gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }
    if ((rc = ibv_modify_qp(qp, &attr, flags)))
        log_err("failed to modify QP state to RTR");
    return rc;
}

int rdma_conn::modify_qp_to_rts()
{
    const int flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
                      IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    struct ibv_qp_attr attr;
    int rc;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = rdma_max_rd_atomic; // FOR READ
    if ((rc = ibv_modify_qp(qp, &attr, flags)))
        log_err("failed to modify QP state to RTS");
    return rc;
}

struct rdma_rinfo
{
    uint32_t type : 2;
    uint32_t id : 30;
    union
    {
        uint32_t rkey;
        uint32_t len;
    };
    uint8_t data[0];
    uint64_t raddr;
};

task<> rdma_conn::update_cache()
{
    auto hdr = (rdma_infomr_hdr *)exchange_mr->addr;
    exchange_wr->sg_list->length = std::min((uint64_t)rdma_info_mr_size - sizeof(rdma_infomr_hdr), hdr->tail + rdma_info_mr_probing);
    assert_check(co_await do_send(exchange_wr, exchange_wr));
    while (crc64(hdr->data, std::min(hdr->tail, (uint64_t)rdma_info_mr_size - sizeof(rdma_infomr_hdr))) != hdr->cksum)
    {
        exchange_wr->sg_list->length = std::min((uint64_t)rdma_info_mr_size - sizeof(rdma_infomr_hdr), hdr->tail + rdma_info_mr_probing);
        assert_check(co_await do_send(exchange_wr, exchange_wr));
    }
    exchange_idx.clear();
    for (uint64_t i = 0; i < hdr->tail;)
    {
        auto info = (rdma_rinfo *)(hdr->data + i);
        if (info->type == rdma_info_type_mr)
        {
            exchange_idx.emplace((uint32_t)info->id, *(rdma_rmr *)(hdr->data + i));
            i += sizeof(rdma_rmr);
        }
        else if (info->type == rdma_info_type_mmap)
        {
            exchange_idx.emplace((uint32_t)info->id, std::string((char *)info->data, info->len));
            i += sizeof(rdma_rmmap) + info->len;
        }
        else
            log_err("unknown info type");
    }
}

task<rdma_rmr> rdma_conn::query_remote_mr(uint32_t mr_id)
{
    if (!exchange_idx.contains(mr_id))
        co_await update_cache();
    if (exchange_idx.contains(mr_id))
        if (auto res = std::get_if<rdma_rmr>(&exchange_idx[mr_id]))
            co_return *res;
    log_err("mr not found");
    co_return rdma_rmr{};
}

#ifdef ENABLE_DOCA_DMA
task<std::tuple<doca_mmap *, uint64_t>> rdma_conn::query_remote_mmap(uint32_t mmap_id)
{
    doca_mmap *mmp = nullptr;
    uint64_t addr = 0;
    if (!exchange_idx.contains(mmap_id))
        co_await update_cache();
    if (exchange_idx.contains(mmap_id))
        if (auto res = std::get_if<std::string>(&exchange_idx[mmap_id]))
        {
            assert_check(doca_mmap_create_from_export(std::to_string(mmap_id).c_str(), (uint8_t *)res->c_str(), res->length(), worker->dev.dma_dev, &mmp) == DOCA_SUCCESS);
            std::tie(addr, std::ignore) = get_addrlen_from_export(*res);
        }
    co_return std::make_tuple(mmp, addr);
}

void dma_future::await_resume()
{
    if (src_buf && doca_buf_refcount_rm(src_buf, nullptr) != DOCA_SUCCESS)
        log_warn("failed to free src buf");
    if (dst_buf && doca_buf_refcount_rm(dst_buf, nullptr) != DOCA_SUCCESS)
        log_warn("failed to free dst buf");
}

void *dma_buf_future::await_resume()
{
    dma_future::await_resume();
    return res_buf;
}

inline void fill_dma_job(doca_dma_job_memcpy *dma_job, doca_ctx *dma_ctx, doca_buf *src_buf, doca_buf *dst_buf, size_t len)
{
    dma_job->base.type = DOCA_DMA_JOB_MEMCPY;
    dma_job->base.flags = DOCA_JOB_FLAGS_NONE;
    dma_job->base.ctx = dma_ctx;
    dma_job->src_buff = src_buf;
    dma_job->dst_buff = dst_buf;
    dma_job->num_bytes_to_copy = len;
}

dma_buf_future rdma_conn::dma_read(doca_mmap *rmmp, uint64_t raddr, size_t len)
{
    auto [buf, job] = alloc_many(len, sizeof(doca_dma_job_memcpy));
    assert_check(buf);
    doca_buf *src_buf, *dst_buf;
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, rmmp, (char *)raddr, len, &src_buf) == DOCA_SUCCESS);
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, worker->mpmmp, (char *)buf, len, &dst_buf) == DOCA_SUCCESS);
    auto dma_job = (doca_dma_job_memcpy *)job;
    fill_dma_job(dma_job, worker->dma_ctx, src_buf, dst_buf, len);
    assert_check(doca_workq_submit(worker->dma_workq, &dma_job->base) == DOCA_SUCCESS);
    return dma_buf_future(worker, src_buf, dst_buf, buf);
}

dma_future rdma_conn::dma_read(doca_mmap *rmmp, uint64_t raddr, doca_mmap *lmmp, void *laddr, size_t len)
{
    auto dma_job = (doca_dma_job_memcpy *)alloc_buf(sizeof(doca_dma_job_memcpy));
    assert_check(dma_job);
    doca_buf *src_buf, *dst_buf;
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, rmmp, (char *)raddr, len, &src_buf) == DOCA_SUCCESS);
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, lmmp, (char *)laddr, len, &dst_buf) == DOCA_SUCCESS);
    fill_dma_job(dma_job, worker->dma_ctx, src_buf, dst_buf, len);
    assert_check(doca_workq_submit(worker->dma_workq, &dma_job->base) == DOCA_SUCCESS);
    auto res = dma_future(worker, src_buf, dst_buf);
    free_buf(dma_job);
    return res;
}

dma_future rdma_conn::dma_write(doca_mmap *rmmp, uint64_t raddr, doca_mmap *lmmp, void *laddr, size_t len)
{
    auto dma_job = (doca_dma_job_memcpy *)alloc_buf(sizeof(doca_dma_job_memcpy));
    assert_check(dma_job);
    doca_buf *src_buf, *dst_buf;
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, rmmp, (char *)raddr, len, &dst_buf) == DOCA_SUCCESS);
    assert_check(doca_buf_inventory_buf_by_addr(worker->buf_inv, lmmp, (char *)laddr, len, &src_buf) == DOCA_SUCCESS);
    fill_dma_job(dma_job, worker->dma_ctx, src_buf, dst_buf, len);
    assert_check(doca_workq_submit(worker->dma_workq, &dma_job->base) == DOCA_SUCCESS);
    auto res = dma_future(worker, src_buf, dst_buf);
    free_buf(dma_job);
    return res;
}
#endif

rdma_future rdma_conn::do_send(ibv_send_wr *wr_begin, ibv_send_wr *wr_end)
{
    auto cor = worker->alloc_coro(conn_id);
    assert_check(cor);
    wr_end->wr_id = cor->id;
    wr_end->send_flags |= IBV_SEND_SIGNALED;
    ibv_send_wr *bad;
    assert_check(0 == ibv_post_send(qp, wr_begin, &bad));
    return rdma_future(cor, this);
}

rdma_future rdma_conn::do_recv(ibv_recv_wr *wr)
{
    auto cor = worker->alloc_coro(conn_id);
    assert_check(cor);
    wr->wr_id = cor->id;
    ibv_recv_wr *bad;
    assert_check(0 == ibv_post_recv(qp, wr, &bad));
    return rdma_future(cor, this);
}

int rdma_future::await_resume()
{
    if (conn && cor)
        conn->worker->free_coro(cor);
    return !(cor->coro_state & coro_state_error); // single thread thus cor is vaild after free
}

void *rdma_buffer_future::await_resume()
{
    if (!rdma_future::await_resume())
    {
        conn->free_buf(_res_buf);
        return nullptr;
    }
    return _res_buf;
}

int rdma_cas_future::await_resume()
{
    conn->free_buf(_res_buf); // single thread thus buf is vaild after free
    if (!rdma_future::await_resume())
        return false;
    auto res = *(uint64_t *)_res_buf == _cmpval;
    _cmpval = *(uint64_t *)_res_buf;
    return res;
}

int rdma_cas_n_future::await_resume()
{
    conn->free_buf(_res_buf);
    if (!rdma_future::await_resume())
        return false;
    return *(uint64_t *)_res_buf == _cmpval;
}

uint64_t rdma_faa_future::await_resume()
{
    conn->free_buf(_res_buf);
    if (!rdma_future::await_resume())
        throw "faa failed";
    return *(uint64_t *)_res_buf;
}

rdma_buffer_future rdma_conn::read(uint64_t raddr, uint32_t rkey, uint32_t len)
{
    auto [buf, sge, wr] = alloc_many(len, sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_RDMA_READ>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, len, lkey());
    auto fur = do_send(send_wr, send_wr);
    return rdma_buffer_future(fur.cor, fur.conn, buf);
}

rdma_future rdma_conn::read(uint64_t raddr, uint32_t rkey, void *laddr, uint32_t len, uint32_t lkey)
{
    if(raddr==0){
        log_err("zero raddr");
        // exit(-1);
        int* ptr = NULL;
        *ptr = 10; // 在这里引发段错误
    }
    auto [sge, wr] = alloc_many(sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(sge);
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_RDMA_READ>(send_wr, (ibv_sge *)sge, raddr, rkey, laddr, len, lkey);
    auto res = do_send(send_wr, send_wr);
    free_buf(sge);
    return res;
}

rdma_future rdma_conn::write(uint64_t raddr, uint32_t rkey, void *laddr, uint32_t len, uint32_t _lkey)
{
    if(raddr==0){
        log_err("zero raddr");
        // exit(-1);
        int* ptr = NULL;
        *ptr = 10; // 在这里引发段错误
    }
    auto [sge,wr] = alloc_many(sizeof(ibv_sge),sizeof(ibv_send_wr));
    assert_check(sge);
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_RDMA_WRITE>(send_wr, (ibv_sge *)sge, raddr, rkey, laddr, len, _lkey);
    if (_lkey == 0)
        send_wr->send_flags = IBV_SEND_INLINE;
    auto res = do_send(send_wr, send_wr);
    free_buf(sge);
    
    //For Flush
    // auto [sge,wr,rr] = alloc_many(sizeof(ibv_sge), sizeof(ibv_send_wr),sizeof(ibv_send_wr));
    // assert_check(sge);
    // auto send_wr = (ibv_send_wr *)wr;
    // auto read_wr = (ibv_send_wr *)rr;
    // fill_rw_wr<IBV_WR_RDMA_WRITE>(send_wr, (ibv_sge *)sge, raddr, rkey, laddr, len, _lkey);
    // fill_rw_wr<IBV_WR_RDMA_READ>(read_wr, (ibv_sge *)sge, raddr, rkey, laddr, len, _lkey);
    // send_wr->next = read_wr;
    // if (_lkey == 0)
    //     send_wr->send_flags = IBV_SEND_INLINE;
    // auto res = do_send(send_wr, send_wr);
    // free_buf(sge);
    return res;
}

void rdma_conn::pure_write(uint64_t raddr, uint32_t rkey, void *laddr, uint32_t len, uint32_t _lkey)
{    
    if(raddr==0){
        log_err("zero raddr");
        // exit(-1);
        int* ptr = NULL;
        *ptr = 10; // 在这里引发段错误
    }
    auto [sge,wr] = alloc_many(sizeof(ibv_sge),sizeof(ibv_send_wr));
    assert_check(sge);
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_RDMA_WRITE>(send_wr, (ibv_sge *)sge, raddr, rkey, laddr, len, _lkey);
    if (_lkey == 0)
        send_wr->send_flags = IBV_SEND_INLINE;
    send_wr->wr_id = wr_wo_await;
    send_wr->send_flags |= IBV_SEND_SIGNALED;
    ibv_send_wr *bad;
    int res = ibv_post_send(qp, send_wr, &bad);
    if(res!=0){
        log_err("res:%d",res);
    }
    assert_check(0 == res);
    free_buf(sge);
}

// rdma_cas_future rdma_conn::fetch_add(uint64_t raddr, uint32_t rkey, uint64_t &cmpval, uint64_t swapval)
rdma_cas_future rdma_conn::fetch_add(uint64_t raddr, uint32_t rkey, uint64_t &fetch, uint64_t addval)
{
    auto [buf, sge, wr] = alloc_many(sizeof(uint64_t), sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    auto send_wr = (ibv_send_wr *)wr;
    fill_atomic_wr<IBV_WR_ATOMIC_FETCH_AND_ADD>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, lkey(), addval, 0);
    auto fur = do_send(send_wr, send_wr);
    return rdma_cas_future(fur.cor, fur.conn, buf, fetch);
}

rdma_cas_future rdma_conn::cas(uint64_t raddr, uint32_t rkey, uint64_t &cmpval, uint64_t swapval)
{
    if(raddr==0){
        log_err("zero raddr");
        // exit(-1);
        int* ptr = NULL;
        *ptr = 10; // 在这里引发段错误
    }
    auto [buf, sge, wr] = alloc_many(sizeof(uint64_t), sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    auto send_wr = (ibv_send_wr *)wr;
    fill_atomic_wr<IBV_WR_ATOMIC_CMP_AND_SWP>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, lkey(), cmpval, swapval);
    auto fur = do_send(send_wr, send_wr);
    return rdma_cas_future(fur.cor, fur.conn, buf, cmpval);
}

rdma_cas_n_future rdma_conn::cas_n(uint64_t raddr, uint32_t rkey, uint64_t cmpval, uint64_t swapval)
{
    if(raddr==0){
        log_err("zero raddr");
        // exit(-1);
        int* ptr = NULL;
        *ptr = 10; // 在这里引发段错误
    }
    auto [buf, sge, wr] = alloc_many(sizeof(uint64_t), sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    auto send_wr = (ibv_send_wr *)wr;
    fill_atomic_wr<IBV_WR_ATOMIC_CMP_AND_SWP>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, lkey(), cmpval, swapval);
    auto fur = do_send(send_wr, send_wr);
    return rdma_cas_n_future(fur.cor, fur.conn, buf, cmpval);
}

rdma_faa_future rdma_conn::faa(uint64_t raddr, uint32_t rkey, uint64_t addval)
{
    auto [buf, sge, wr] = alloc_many(sizeof(uint64_t), sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    auto send_wr = (ibv_send_wr *)wr;
    fill_atomic_wr<IBV_WR_ATOMIC_FETCH_AND_ADD>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, lkey(), addval, 0);
    auto fur = do_send(send_wr, send_wr);
    return rdma_faa_future(fur.cor, fur.conn, buf);
}

rdma_future rdma_conn::send(void *laddr, uint32_t len, uint32_t _lkey)
{
    auto [sge, wr] = alloc_many(sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(sge);
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_SEND>(send_wr, (ibv_sge *)sge, 0, 0, laddr, len, _lkey);
    if (_lkey == 0)
        send_wr->send_flags = IBV_SEND_INLINE;
    auto res = do_send(send_wr, send_wr);
    free_buf(sge);
    return res;
}

rdma_buffer_future rdma_conn::recv(uint32_t len)
{
    auto [buf, sge, wr] = alloc_many(len, sizeof(ibv_sge), sizeof(ibv_recv_wr));
    assert_check(buf);
    auto recv_wr = (ibv_recv_wr *)wr;
    fill_recv_wr(recv_wr, (ibv_sge *)sge, buf, len, lkey());
    auto fur = do_recv(recv_wr);
    return rdma_buffer_future(fur.cor, fur.conn, buf);
}

rdma_future rdma_conn::recv(void *laddr, uint32_t len, uint32_t lkey)
{
    auto [sge, wr] = alloc_many(sizeof(ibv_sge), sizeof(ibv_recv_wr));
    assert_check(sge);
    auto recv_wr = (ibv_recv_wr *)wr;
    fill_recv_wr(recv_wr, (ibv_sge *)sge, laddr, len, lkey);
    auto fur = do_recv(recv_wr);
    free_buf(sge);
    return fur;
}

task<uint32_t> rdma_conn::fill(uint64_t raddr, uint32_t rkey, uint32_t rlen, void *fill_val, uint32_t fill_val_len, uint32_t work_buf_size)
{
    assert_check(is_times_ofN(work_buf_size, fill_val_len));
    auto [buf, sge, wr] = alloc_many(work_buf_size, sizeof(ibv_sge), sizeof(ibv_send_wr));
    assert_check(buf);
    uint32_t filled = 0;
    for (uint8_t *wbuf = (uint8_t *)buf; filled < work_buf_size;)
    {
        memcpy(wbuf, fill_val, fill_val_len);
        filled += fill_val_len;
        wbuf += fill_val_len;
    }
    auto send_wr = (ibv_send_wr *)wr;
    fill_rw_wr<IBV_WR_RDMA_WRITE>(send_wr, (ibv_sge *)sge, raddr, rkey, buf, work_buf_size, lkey());
    filled = 0;
    for (; filled + work_buf_size <= rlen;)
    {
        if (!co_await do_send(send_wr, send_wr))
            co_return filled;
        send_wr->wr.rdma.remote_addr += work_buf_size;
        filled += work_buf_size;
    }
    if (filled < rlen)
    {
        send_wr->sg_list->length = rlen - filled;
        if (!co_await do_send(send_wr, send_wr))
            co_return filled;
        filled = rlen;
    }
    free_buf(buf);
    co_return filled;
}

#ifdef ENABLE_DOCA_DMA
void free_mmap(doca_mmap *mmp)
{
    if (doca_mmap_destroy(mmp) != DOCA_SUCCESS)
        log_warn("failed to destroy mmap");
}
std::tuple<uint64_t, uint64_t> get_addrlen_from_export(std::string &export_str)
{
    struct json_object *from_export_json;
    struct json_object *addr;
    struct json_object *jlen;
    from_export_json = json_tokener_parse(export_str.c_str());
    json_object_object_get_ex(from_export_json, "addr", &addr);
    json_object_object_get_ex(from_export_json, "len", &jlen);
    auto res = std::make_tuple(json_object_get_int64(addr), json_object_get_int64(jlen));
    json_object_put(from_export_json);
    return res;
}
#endif

// crc64 impl
static const uint64_t crc64_tab[256] = {0x0000000000000000ULL, 0x7ad870c830358979ULL, 0xf5b0e190606b12f2ULL, 0x8f689158505e9b8bULL, 0xc038e5739841b68fULL, 0xbae095bba8743ff6ULL, 0x358804e3f82aa47dULL, 0x4f50742bc81f2d04ULL, 0xab28ecb46814fe75ULL, 0xd1f09c7c5821770cULL, 0x5e980d24087fec87ULL, 0x24407dec384a65feULL, 0x6b1009c7f05548faULL, 0x11c8790fc060c183ULL, 0x9ea0e857903e5a08ULL, 0xe478989fa00bd371ULL, 0x7d08ff3b88be6f81ULL, 0x07d08ff3b88be6f8ULL, 0x88b81eabe8d57d73ULL, 0xf2606e63d8e0f40aULL, 0xbd301a4810ffd90eULL, 0xc7e86a8020ca5077ULL, 0x4880fbd87094cbfcULL, 0x32588b1040a14285ULL, 0xd620138fe0aa91f4ULL, 0xacf86347d09f188dULL, 0x2390f21f80c18306ULL, 0x594882d7b0f40a7fULL, 0x1618f6fc78eb277bULL, 0x6cc0863448deae02ULL, 0xe3a8176c18803589ULL, 0x997067a428b5bcf0ULL, 0xfa11fe77117cdf02ULL, 0x80c98ebf2149567bULL, 0x0fa11fe77117cdf0ULL, 0x75796f2f41224489ULL, 0x3a291b04893d698dULL, 0x40f16bccb908e0f4ULL, 0xcf99fa94e9567b7fULL, 0xb5418a5cd963f206ULL, 0x513912c379682177ULL, 0x2be1620b495da80eULL, 0xa489f35319033385ULL, 0xde51839b2936bafcULL, 0x9101f7b0e12997f8ULL, 0xebd98778d11c1e81ULL, 0x64b116208142850aULL, 0x1e6966e8b1770c73ULL, 0x8719014c99c2b083ULL, 0xfdc17184a9f739faULL, 0x72a9e0dcf9a9a271ULL, 0x08719014c99c2b08ULL, 0x4721e43f0183060cULL, 0x3df994f731b68f75ULL, 0xb29105af61e814feULL, 0xc849756751dd9d87ULL, 0x2c31edf8f1d64ef6ULL, 0x56e99d30c1e3c78fULL, 0xd9810c6891bd5c04ULL, 0xa3597ca0a188d57dULL, 0xec09088b6997f879ULL, 0x96d1784359a27100ULL, 0x19b9e91b09fcea8bULL, 0x636199d339c963f2ULL, 0xdf7adabd7a6e2d6fULL, 0xa5a2aa754a5ba416ULL, 0x2aca3b2d1a053f9dULL, 0x50124be52a30b6e4ULL, 0x1f423fcee22f9be0ULL, 0x659a4f06d21a1299ULL, 0xeaf2de5e82448912ULL, 0x902aae96b271006bULL, 0x74523609127ad31aULL, 0x0e8a46c1224f5a63ULL, 0x81e2d7997211c1e8ULL, 0xfb3aa75142244891ULL, 0xb46ad37a8a3b6595ULL, 0xceb2a3b2ba0eececULL, 0x41da32eaea507767ULL, 0x3b024222da65fe1eULL, 0xa2722586f2d042eeULL, 0xd8aa554ec2e5cb97ULL, 0x57c2c41692bb501cULL, 0x2d1ab4dea28ed965ULL, 0x624ac0f56a91f461ULL, 0x1892b03d5aa47d18ULL, 0x97fa21650afae693ULL, 0xed2251ad3acf6feaULL, 0x095ac9329ac4bc9bULL, 0x7382b9faaaf135e2ULL, 0xfcea28a2faafae69ULL, 0x8632586aca9a2710ULL, 0xc9622c4102850a14ULL, 0xb3ba5c8932b0836dULL, 0x3cd2cdd162ee18e6ULL, 0x460abd1952db919fULL, 0x256b24ca6b12f26dULL, 0x5fb354025b277b14ULL, 0xd0dbc55a0b79e09fULL, 0xaa03b5923b4c69e6ULL, 0xe553c1b9f35344e2ULL, 0x9f8bb171c366cd9bULL, 0x10e3202993385610ULL, 0x6a3b50e1a30ddf69ULL, 0x8e43c87e03060c18ULL, 0xf49bb8b633338561ULL, 0x7bf329ee636d1eeaULL, 0x012b592653589793ULL, 0x4e7b2d0d9b47ba97ULL, 0x34a35dc5ab7233eeULL, 0xbbcbcc9dfb2ca865ULL, 0xc113bc55cb19211cULL, 0x5863dbf1e3ac9decULL, 0x22bbab39d3991495ULL, 0xadd33a6183c78f1eULL, 0xd70b4aa9b3f20667ULL, 0x985b3e827bed2b63ULL, 0xe2834e4a4bd8a21aULL, 0x6debdf121b863991ULL, 0x1733afda2bb3b0e8ULL, 0xf34b37458bb86399ULL, 0x8993478dbb8deae0ULL, 0x06fbd6d5ebd3716bULL, 0x7c23a61ddbe6f812ULL, 0x3373d23613f9d516ULL, 0x49aba2fe23cc5c6fULL, 0xc6c333a67392c7e4ULL, 0xbc1b436e43a74e9dULL, 0x95ac9329ac4bc9b5ULL, 0xef74e3e19c7e40ccULL, 0x601c72b9cc20db47ULL, 0x1ac40271fc15523eULL, 0x5594765a340a7f3aULL, 0x2f4c0692043ff643ULL, 0xa02497ca54616dc8ULL, 0xdafce7026454e4b1ULL, 0x3e847f9dc45f37c0ULL, 0x445c0f55f46abeb9ULL, 0xcb349e0da4342532ULL, 0xb1eceec59401ac4bULL, 0xfebc9aee5c1e814fULL, 0x8464ea266c2b0836ULL, 0x0b0c7b7e3c7593bdULL, 0x71d40bb60c401ac4ULL, 0xe8a46c1224f5a634ULL, 0x927c1cda14c02f4dULL, 0x1d148d82449eb4c6ULL, 0x67ccfd4a74ab3dbfULL, 0x289c8961bcb410bbULL, 0x5244f9a98c8199c2ULL, 0xdd2c68f1dcdf0249ULL, 0xa7f41839ecea8b30ULL, 0x438c80a64ce15841ULL, 0x3954f06e7cd4d138ULL, 0xb63c61362c8a4ab3ULL, 0xcce411fe1cbfc3caULL, 0x83b465d5d4a0eeceULL, 0xf96c151de49567b7ULL, 0x76048445b4cbfc3cULL, 0x0cdcf48d84fe7545ULL, 0x6fbd6d5ebd3716b7ULL, 0x15651d968d029fceULL, 0x9a0d8ccedd5c0445ULL, 0xe0d5fc06ed698d3cULL, 0xaf85882d2576a038ULL, 0xd55df8e515432941ULL, 0x5a3569bd451db2caULL, 0x20ed197575283bb3ULL, 0xc49581ead523e8c2ULL, 0xbe4df122e51661bbULL, 0x3125607ab548fa30ULL, 0x4bfd10b2857d7349ULL, 0x04ad64994d625e4dULL, 0x7e7514517d57d734ULL, 0xf11d85092d094cbfULL, 0x8bc5f5c11d3cc5c6ULL, 0x12b5926535897936ULL, 0x686de2ad05bcf04fULL, 0xe70573f555e26bc4ULL, 0x9ddd033d65d7e2bdULL, 0xd28d7716adc8cfb9ULL, 0xa85507de9dfd46c0ULL, 0x273d9686cda3dd4bULL, 0x5de5e64efd965432ULL, 0xb99d7ed15d9d8743ULL, 0xc3450e196da80e3aULL, 0x4c2d9f413df695b1ULL, 0x36f5ef890dc31cc8ULL, 0x79a59ba2c5dc31ccULL, 0x037deb6af5e9b8b5ULL, 0x8c157a32a5b7233eULL, 0xf6cd0afa9582aa47ULL, 0x4ad64994d625e4daULL, 0x300e395ce6106da3ULL, 0xbf66a804b64ef628ULL, 0xc5bed8cc867b7f51ULL, 0x8aeeace74e645255ULL, 0xf036dc2f7e51db2cULL, 0x7f5e4d772e0f40a7ULL, 0x05863dbf1e3ac9deULL, 0xe1fea520be311aafULL, 0x9b26d5e88e0493d6ULL, 0x144e44b0de5a085dULL, 0x6e963478ee6f8124ULL, 0x21c640532670ac20ULL, 0x5b1e309b16452559ULL, 0xd476a1c3461bbed2ULL, 0xaeaed10b762e37abULL, 0x37deb6af5e9b8b5bULL, 0x4d06c6676eae0222ULL, 0xc26e573f3ef099a9ULL, 0xb8b627f70ec510d0ULL, 0xf7e653dcc6da3dd4ULL, 0x8d3e2314f6efb4adULL, 0x0256b24ca6b12f26ULL, 0x788ec2849684a65fULL, 0x9cf65a1b368f752eULL, 0xe62e2ad306bafc57ULL, 0x6946bb8b56e467dcULL, 0x139ecb4366d1eea5ULL, 0x5ccebf68aecec3a1ULL, 0x2616cfa09efb4ad8ULL, 0xa97e5ef8cea5d153ULL, 0xd3a62e30fe90582aULL, 0xb0c7b7e3c7593bd8ULL, 0xca1fc72bf76cb2a1ULL, 0x45775673a732292aULL, 0x3faf26bb9707a053ULL, 0x70ff52905f188d57ULL, 0x0a2722586f2d042eULL, 0x854fb3003f739fa5ULL, 0xff97c3c80f4616dcULL, 0x1bef5b57af4dc5adULL, 0x61372b9f9f784cd4ULL, 0xee5fbac7cf26d75fULL, 0x9487ca0fff135e26ULL, 0xdbd7be24370c7322ULL, 0xa10fceec0739fa5bULL, 0x2e675fb4576761d0ULL, 0x54bf2f7c6752e8a9ULL, 0xcdcf48d84fe75459ULL, 0xb71738107fd2dd20ULL, 0x387fa9482f8c46abULL, 0x42a7d9801fb9cfd2ULL, 0x0df7adabd7a6e2d6ULL, 0x772fdd63e7936bafULL, 0xf8474c3bb7cdf024ULL, 0x829f3cf387f8795dULL, 0x66e7a46c27f3aa2cULL, 0x1c3fd4a417c62355ULL, 0x935745fc4798b8deULL, 0xe98f353477ad31a7ULL, 0xa6df411fbfb21ca3ULL, 0xdc0731d78f8795daULL, 0x536fa08fdfd90e51ULL, 0x29b7d047efec8728ULL};

uint64_t crc64(const void *data, size_t l)
{
    uint64_t crc = 0;
    uint8_t *s = (uint8_t *)data;

    for (size_t i = 0; i < l; ++i)
        crc = crc64_tab[(uint8_t)crc ^ s[i]] ^ (crc >> 8);

    return crc;
}