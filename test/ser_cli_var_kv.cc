#include "clevel.h"
#include "clevel_filter.h"
#include "clevel_single_filter.h"
#include "generator.h"
#include "plush.h"
#include "plush_single_filter.h"
#include "race.h"
#include "sephash.h"
#include "split_batch.h"
#include "split_hash.h"
#include "split_hash_idle.h"
#include "split_inline_dep.h"
#include "split_search_base.h"
#include "split_search_fptable.h"
#include <set>
#include <stdint.h>
#define ORDERED_INSERT
Config config;
uint64_t load_num;
using ClientType = SEPHASH::Client;
using ServerType = SEPHASH::Server;
using Slice = SEPHASH::Slice;

constexpr uint64_t key_len = 2;
constexpr uint64_t value_len = 4096;

void GenKey(uint64_t key, uint64_t *tmp_key)
{
    uint64_t data_key;
#ifdef ORDERED_INSERT
    data_key = key;
#else
    data_key = FNVHash64(key);
#endif
    for (int i = 0; i < key_len; i++)
        tmp_key[i] = data_key;
}

template <class Client>
    requires KVTrait<Client, Slice *, Slice *>
task<> load(Client *cli, uint64_t cli_id, uint64_t coro_id)
{
    co_await cli->start(config.num_machine * config.num_cli * config.num_coro);
    uint64_t tmp_key[key_len];
    Slice key, value;
    std::string tmp_value = std::string(value_len, '1');
    value.len = tmp_value.length();
    value.data = (char *)tmp_value.data();
    key.len = key_len * sizeof(uint64_t);
    key.data = (char *)tmp_key;
    uint64_t num_op = load_num / (config.num_machine * config.num_cli * config.num_coro);
    for (uint64_t i = 0; i < num_op; i++)
    {
        GenKey((config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id) * num_op + i,
               tmp_key);
        co_await cli->insert(&key, &value);
    }
    co_await cli->stop();
    co_return;
}

template <class Client>
    requires KVTrait<Client, Slice *, Slice *>
task<> run(Generator *gen, Client *cli, uint64_t cli_id, uint64_t coro_id)
{
    co_await cli->start(config.num_machine * config.num_cli * config.num_coro);
    uint64_t tmp_key[key_len];
    char buffer[8192];
    Slice key, value, ret_value, update_value;

    ret_value.data = buffer;

    std::string tmp_value = std::string(value_len, '1');
    value.len = tmp_value.length();
    value.data = (char *)tmp_value.data();

    std::string tmp_value_2 = std::string(value_len, '2');
    update_value.len = tmp_value_2.length();
    update_value.data = (char *)tmp_value_2.data();

    key.len = key_len * sizeof(uint64_t);
    key.data = (char *)&tmp_key;

    double op_frac;
    double read_frac = config.insert_frac + config.read_frac;
    double update_frac = config.insert_frac + config.read_frac + config.update_frac;
    xoshiro256pp op_chooser;
    xoshiro256pp key_chooser;
    uint64_t num_op = config.num_op / (config.num_machine * config.num_cli * config.num_coro);
    uint64_t load_avr = load_num / (config.num_machine * config.num_cli * config.num_coro);
    // uint64_t load_avr = num_op;
    for (uint64_t i = 0; i < num_op; i++)
    {
        op_frac = op_chooser();
        if (op_frac < config.insert_frac)
        {
            GenKey(load_num +
                       (config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id) *
                           load_avr +
                       gen->operator()(key_chooser()),
                   tmp_key);
            co_await cli->insert(&key, &value);
        }
        else if (op_frac < read_frac)
        {
            ret_value.len = 0;
            GenKey((config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id) *
                           load_avr +
                       gen->operator()(key_chooser()),
                   tmp_key);
            co_await cli->search(&key, &ret_value);
            // if (ret_value.len != value.len || memcmp(ret_value.data, value.data, value.len) != 0)
            // {
            //     log_err("[%lu:%lu]wrong value for key:%lu with value:%s expected:%s", cli_id, coro_id, tmp_key[0],
            //             ret_value.data, value.data);
            //     // exit(-1);
            // }
        }
        else if (op_frac < update_frac)
        {
            // update
            GenKey((config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id) *
                           load_avr +
                       gen->operator()(key_chooser()),
                   tmp_key);
            co_await cli->update(&key, &update_value);
            // auto [slot_ptr, slot] = co_await cli->search(&key, &ret_value);
            // if (slot_ptr == 0ull)
            //     log_err("[%lu:%lu]update for key:%lu result in loss", cli_id, coro_id, tmp_key);
            // else if (ret_value.len != update_value.len || memcmp(ret_value.data, update_value.data, update_value.len)
            // != 0)
            // {
            //     log_err("[%lu:%lu]wrong value for key:%lu with value:%s expected:%s", cli_id, coro_id, tmp_key,
            //             ret_value.data, update_value.data);
            // }
        }
        else
        {
            // delete
            GenKey((config.machine_id * config.num_cli * config.num_coro + cli_id * config.num_coro + coro_id) *
                           load_avr +
                       gen->operator()(key_chooser()),
                   tmp_key);
            co_await cli->remove(&key);
            // uint64_t cnt = 0;
            // while(true){
            //     auto [slot_ptr, slot] = co_await cli->search(&key, &ret_value);
            //     if (slot_ptr != 0ull)
            //         log_err("[%lu:%lu]fail to delete value for key:%lu with slot_ptr:%lx and ret_value:%s", cli_id,
            //         coro_id, tmp_key,slot_ptr,ret_value.data);
            //     else
            //         break;
            //     if(cnt++>=3){
            //         exit(-1);
            //     }
            //     co_await cli->remove(&key);
            // }
        }
    }
    co_await cli->stop();
    co_return;
}

int main(int argc, char *argv[])
{
    config.ParseArg(argc, argv);
    load_num = config.load_num;
    if (config.is_server)
    {
        ServerType ser(config);
        while (true)
            ;
    }
    else
    {
        uint64_t cbuf_size = (1ul << 20) * 500;
        char *mem_buf = (char *)malloc(cbuf_size * (config.num_cli * config.num_coro + 1));
        rdma_dev dev("mlx5_0", 1, config.gid_idx);
        std::vector<ibv_mr *> lmrs(config.num_cli * config.num_coro + 1, nullptr);
        std::vector<rdma_client *> rdma_clis(config.num_cli + 1, nullptr);
        std::vector<rdma_conn *> rdma_conns(config.num_cli + 1, nullptr);
        std::vector<rdma_conn *> rdma_wowait_conns(config.num_cli + 1, nullptr);
        std::mutex dir_lock;
        std::vector<BasicDB *> clis;
        std::thread ths[80];

        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            rdma_clis[i] = new rdma_client(dev, so_qp_cap, rdma_default_tempmp_size, config.max_coro, config.cq_size);
            rdma_conns[i] = rdma_clis[i]->connect(config.server_ip);
            assert(rdma_conns[i] != nullptr);
            rdma_wowait_conns[i] = rdma_clis[i]->connect(config.server_ip);
            assert(rdma_wowait_conns[i] != nullptr);
            for (uint64_t j = 0; j < config.num_coro; j++)
            {
                lmrs[i * config.num_coro + j] =
                    dev.create_mr(cbuf_size, mem_buf + cbuf_size * (i * config.num_coro + j));
                BasicDB *cli;
                cli = new ClientType(config, lmrs[i * config.num_coro + j], rdma_clis[i], rdma_conns[i],
                                     rdma_wowait_conns[i], config.machine_id, i, j);
                clis.push_back(cli);
            }
        }

        // For Rehash Thread
        std::atomic_bool exit_flag{true};
        bool rehash_flag = typeid(ClientType) == typeid(CLEVEL::Client) ||
                           typeid(ClientType) == typeid(ClevelFilter::Client) ||
                           typeid(ClientType) == typeid(ClevelSingleFilter::Client);
        ;

        if (config.machine_id == 0 && rehash_flag)
        {
            rdma_clis[config.num_cli] =
                new rdma_client(dev, so_qp_cap, rdma_default_tempmp_size, config.max_coro, config.cq_size);
            rdma_conns[config.num_cli] = rdma_clis[config.num_cli]->connect(config.server_ip);
            rdma_wowait_conns[config.num_cli] = rdma_clis[config.num_cli]->connect(config.server_ip);

            lmrs[config.num_cli * config.num_coro] =
                dev.create_mr(cbuf_size, mem_buf + cbuf_size * (config.num_cli * config.num_coro));
            ClientType *rehash_cli = new ClientType(
                config, lmrs[config.num_cli * config.num_coro], rdma_clis[config.num_cli], rdma_conns[config.num_cli],
                rdma_wowait_conns[config.num_cli], config.machine_id, config.num_cli, config.num_coro);
            auto th = [&](rdma_client *rdma_cli) {
                // rdma_cli->run(rehash_cli->rehash(exit_flag));
            };
            ths[config.num_cli] = std::thread(th, rdma_clis[config.num_cli]);
        }

        printf("Load start\n");
        auto start = std::chrono::steady_clock::now();
        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            auto th = [&](rdma_client *rdma_cli, uint64_t cli_id) {
                std::vector<task<>> tasks;
                for (uint64_t j = 0; j < config.num_coro; j++)
                {
                    tasks.emplace_back(load((ClientType *)clis[cli_id * config.num_coro + j], cli_id, j));
                }
                rdma_cli->run(gather(std::move(tasks)));
            };
            ths[i] = std::thread(th, rdma_clis[i], i);
        }
        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            ths[i].join();
        }
        auto end = std::chrono::steady_clock::now();
        double op_cnt = 1.0 * load_num;
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        printf("Load duration:%.2lfms\n", duration);
        printf("Load IOPS:%.2lfKops\n", op_cnt / duration);
        fflush(stdout);
        // ths[config.num_cli].join();

        printf("Run start\n");
        auto op_per_coro = config.num_op / (config.num_machine * config.num_cli * config.num_coro);
        std::vector<Generator *> gens;
        for (uint64_t i = 0; i < config.num_cli * config.num_coro; i++)
        {
            if (config.pattern_type == 0)
            {
                gens.push_back(new seq_gen(op_per_coro));
            }
            else if (config.pattern_type == 1)
            {
                gens.push_back(new uniform(op_per_coro));
            }
            else if (config.pattern_type == 2)
            {
                gens.push_back(new zipf99(op_per_coro));
            }
            else
            {
                gens.push_back(new SkewedLatestGenerator(op_per_coro));
            }
        }
        start = std::chrono::steady_clock::now();
        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            auto th = [&](rdma_client *rdma_cli, uint64_t cli_id) {
                std::vector<task<>> tasks;
                for (uint64_t j = 0; j < config.num_coro; j++)
                {
                    tasks.emplace_back(run(gens[cli_id * config.num_coro + j],
                                           (ClientType *)(clis[cli_id * config.num_coro + j]), cli_id, j));
                }
                rdma_cli->run(gather(std::move(tasks)));
            };
            ths[i] = std::thread(th, rdma_clis[i], i);
        }
        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            ths[i].join();
        }
        end = std::chrono::steady_clock::now();
        op_cnt = 1.0 * config.num_op;
        duration = std::chrono::duration<double, std::milli>(end - start).count();
        printf("Run duration:%.2lfms\n", duration);
        printf("Run IOPS:%.2lfKops\n", op_cnt / duration);
        fflush(stdout);

        exit_flag.store(false);
        if (config.machine_id == 0 && rehash_flag)
        {
            ths[config.num_cli].join();
        }
        if (config.machine_id != 0 && rehash_flag)
        {
            rdma_clis[config.num_cli] =
                new rdma_client(dev, so_qp_cap, rdma_default_tempmp_size, config.max_coro, config.cq_size);
            rdma_conns[config.num_cli] = rdma_clis[config.num_cli]->connect(config.server_ip);
            rdma_wowait_conns[config.num_cli] = rdma_clis[config.num_cli]->connect(config.server_ip);

            lmrs[config.num_cli * config.num_coro] =
                dev.create_mr(cbuf_size, mem_buf + cbuf_size * (config.num_cli * config.num_coro));
            ClientType *check_cli = new ClientType(
                config, lmrs[config.num_cli * config.num_coro], rdma_clis[config.num_cli], rdma_conns[config.num_cli],
                rdma_wowait_conns[config.num_cli], config.machine_id, config.num_cli, config.num_coro);

            auto th = [&](rdma_client *rdma_cli) {
                // while(rdma_cli->run(check_cli->check_exit())){
                // log_err("waiting for rehash exit");
                // }
            };
            ths[config.num_cli] = std::thread(th, rdma_clis[config.num_cli]);
            ths[config.num_cli].join();
        }

        if (config.machine_id == 0)
        {
            // rdma_clis[0]->run(((ClientType*)clis[0])->cal_utilization());
        }

        for (auto gen : gens)
        {
            delete gen;
        }

        // Reset Ser
        if (config.machine_id == 0)
        {
            rdma_clis[0]->run(((ClientType *)clis[0])->reset_remote());
        }

        free(mem_buf);
        for (uint64_t i = 0; i < config.num_cli; i++)
        {
            for (uint64_t j = 0; j < config.num_coro; j++)
            {
                rdma_free_mr(lmrs[i * config.num_coro + j], false);
                delete clis[i * config.num_coro + j];
            }
            delete rdma_wowait_conns[i];
            delete rdma_conns[i];
            delete rdma_clis[i];
        }
    }
}