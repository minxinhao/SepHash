#pragma once
#include <stdint.h>
#include "cmdline.h"

struct Config
{
    bool is_server;
    const char *server_ip;
    uint64_t num_machine;
    uint64_t machine_id;
    uint64_t num_cli;
    uint64_t num_coro;
    uint64_t gid_idx;
    uint64_t max_coro;
    uint64_t cq_size;
    uint64_t mem_size;
    uint64_t num_op;
    uint64_t read_size;
    uint64_t load_num;
    char work_load; // YCSB : a,b,c,d; e有scan,f有RMW，暂时不弄了

    // Internel States For YCSB
    uint64_t pattern_type; // Seq : 0 , Uniform : 1 , Zipfian : 2 , Latest : 3
    double insert_frac;
    double read_frac;
    double update_frac;
    double delete_frac;

    void ParseArg(int argc, char *argv[])
    {
        cmdline::parser cmd_parser;
        cmd_parser.add("server", 'a', "Is a server or client");
        cmd_parser.add<std::string>("server_ip", 'b', "IP address of server", false);
        cmd_parser.add<uint64_t>("num_cli", 'c', "Number of client", false, 4, cmdline::range(1, 80));
        cmd_parser.add<uint64_t>("num_machine", 'd', "Number of client", false, 4, cmdline::range(1, 80));
        cmd_parser.add<uint64_t>("gid_idx", 'e', "gid index");
        cmd_parser.add<uint64_t>("max_coro", 'f', "Number of max coroutine in each thread", false, 256);
        cmd_parser.add<uint64_t>("cq_size", 'g', "size of complete queue", false, 64);
        cmd_parser.add<uint64_t>("mem_size", 'i', "size of pm_file", false, (1ul << 30) * 50);
        cmd_parser.add<uint64_t>("num_op", 'j', "Number of inserted key by every thread", false, 1000000);
        cmd_parser.add<uint64_t>("num_coro", 'k', "Number of coro", false, 4, cmdline::range(1, 80));
        cmd_parser.add<uint64_t>("machine_id", 'l', "machine_id", false, 0, cmdline::range(0, 10));
        cmd_parser.add<uint64_t>("pattern_type", 'm', "pattern_type", false, 0, cmdline::range(0, 3));
        cmd_parser.add<double>("insert_frac", 'n', "insert_frac", false, 1.0);
        cmd_parser.add<double>("read_frac", 'o', "read_frac", false, 0.0);
        cmd_parser.add<double>("update_frac", 'p', "update_frac", false, 0.0);
        cmd_parser.add<double>("delete_frac", 'q', "delete_frac", false, 0.0);
        cmd_parser.add<uint64_t>("read_size", 'r', "read_size", false, 64);
        cmd_parser.add<uint64_t>("load_num", 's', "load_num", false, 10000);

        cmd_parser.parse_check(argc, argv);

        is_server = cmd_parser.exist("server");
        server_ip = cmd_parser.get<std::string>("server_ip").c_str();
        num_machine = cmd_parser.get<uint64_t>("num_machine");
        num_cli = cmd_parser.get<uint64_t>("num_cli");
        num_coro = cmd_parser.get<uint64_t>("num_coro");
        machine_id = cmd_parser.get<uint64_t>("machine_id");
        gid_idx = cmd_parser.get<uint64_t>("gid_idx");
        max_coro = cmd_parser.get<uint64_t>("max_coro");
        cq_size = cmd_parser.get<uint64_t>("cq_size");
        mem_size = cmd_parser.get<uint64_t>("mem_size");
        num_op = cmd_parser.get<uint64_t>("num_op");
        pattern_type = cmd_parser.get<uint64_t>("pattern_type");
        insert_frac = cmd_parser.get<double>("insert_frac");
        read_frac = cmd_parser.get<double>("read_frac");
        update_frac = cmd_parser.get<double>("update_frac");
        delete_frac = cmd_parser.get<double>("delete_frac");
        read_size = cmd_parser.get<uint64_t>("read_size");
        load_num = cmd_parser.get<uint64_t>("load_num");

        if(insert_frac + update_frac + read_frac + delete_frac != 1.0){
            printf("err fraction of operations\n");
            print();
            exit(-1);
        }
        // print();
    }

    void print()
    {
        printf("Configuraion\n");
        printf("is_server                 = %s\n", is_server ? "true" : "false");
        printf("server_ip                 = %s\n", server_ip);
        printf("machine_id                 = %lu\n", machine_id);
        printf("gid_idx                 = %lu\n", gid_idx);
        printf("max_coro                 = %ld\n", max_coro);
        printf("cq_size                 = %ld\n", cq_size);
        printf("num_machine                 = %ld\n", num_machine);
        printf("num_cli                 = %ld\n", num_cli);
        printf("num_coro                 = %ld\n", num_coro);
        printf("num_op                 = %ld\n", num_op);
        printf("End of Configuraion\n");
    }
};