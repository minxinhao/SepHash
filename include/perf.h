#pragma once
//定义一些通用的结构体
#include <stdint.h>
#include <map>
#include <string>
#include <chrono>
#include <iostream>
#include <fstream>
#include <vector>
// #define USE_PERF
// #define USE_SUM_COST

struct Perf
{
    //用于性能统计
    std::vector<double> insert_lat;
    std::vector<double> search_lat;

    std::chrono::high_resolution_clock::time_point start;
    std::chrono::high_resolution_clock::time_point end;
    
    void init(){
        insert_lat.reserve(10000000);
        search_lat.reserve(1000000);
    }

    void init(uint64_t insert_num,uint64_t search_num){
        insert_lat.reserve(insert_num);
        search_lat.reserve(search_num);
    }

    void start_perf(){
#ifdef USE_PERF
        start = std::chrono::high_resolution_clock::now();
#endif
    }

    void push_insert(){
#ifdef USE_PERF
        end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::micro>(end - start).count();
        insert_lat.push_back(duration);
#endif
    }

    void push_search(){
#ifdef USE_PERF
        end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::micro>(end - start).count();
        search_lat.push_back(duration);
#endif
    }

    void to_file(const char* file_name,std::vector<double>& lat){
#ifdef USE_PERF
        std::ofstream file(file_name, std::ios::out); // 创建文件输出流，指定打开模式为覆盖写入
        if (file.is_open()) {
            // 将时延数据写入文件
            for (const auto& latency : lat) {
                file << latency << "\n"; // 每个时延一行
            }
            file.close(); // 关闭文件
            std::cout << "Data exported to file: " <<file_name<< std::endl;
        } else {
            std::cout << "Failed to open the output file." << std::endl;
        }
#endif
    }

    void print(uint64_t cli_id,uint64_t coro_id){
#ifdef USE_PERF
        std::string insert_file_name = "insert_lat" + std::to_string(cli_id) + std::to_string(coro_id)+".txt";
        to_file(insert_file_name.c_str(),insert_lat);
        std::string search_file_name = "search_lat" + std::to_string(cli_id) + std::to_string(coro_id)+".txt";
        to_file(search_file_name.c_str(),search_lat);
#endif
    }

};

struct SumCost
{
    //用于性能统计
    uint64_t merge_cnt = 0;
    uint64_t split_cnt = 0;
    double merge_time = 0;
    double split_time = 0;
    double insert_time = 0;
    std::vector<uint64_t> retry_cnt;
    std::vector<uint64_t> level_cnt;

    std::chrono::high_resolution_clock::time_point merge_start;
    std::chrono::high_resolution_clock::time_point split_start;
    std::chrono::high_resolution_clock::time_point insert_start;
    

    void init(){
        retry_cnt.reserve(10000000);
        level_cnt.reserve(1000000);
    }

    void init(uint64_t insert_num,uint64_t search_num){
        retry_cnt.reserve(insert_num);
        level_cnt.reserve(search_num);
    }

    void push_retry_cnt(uint64_t retry){
#ifdef USE_SUM_COST
        retry_cnt.emplace_back(retry);
#endif
    }

    void push_level_cnt(uint64_t level){
#ifdef USE_SUM_COST
        level_cnt.emplace_back(level);
#endif
    }

    void start_insert(){
#ifdef USE_SUM_COST
        insert_start = std::chrono::high_resolution_clock::now();
#endif
    }

    void end_insert(){
#ifdef USE_SUM_COST
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::micro>(end - insert_start).count();
        insert_time += duration;
#endif
    }

    void start_merge(){
#ifdef USE_SUM_COST
        merge_start = std::chrono::high_resolution_clock::now();
#endif
    }

    void end_merge(){
#ifdef USE_SUM_COST
        merge_cnt++;
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::micro>(end - merge_start).count();
        merge_time += duration;
#endif
    }

    void add_split_cnt(){
        split_cnt++;
    }

    void start_split(){
#ifdef USE_SUM_COST
        // split_cnt++;
        split_start = std::chrono::high_resolution_clock::now();
#endif
    }

    void end_split(){
#ifdef USE_SUM_COST
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::micro>(end - split_start).count();
        split_time += duration;
#endif
    }


    void to_file(const char* file_name,std::vector<uint64_t>& lat){
#ifdef USE_SUM_COST
        std::ofstream file(file_name, std::ios::out); // 创建文件输出流，指定打开模式为覆盖写入
        if (file.is_open()) {
            // 将时延数据写入文件
            for (const auto& latency : lat) {
                file << latency << "\n"; // 每个时延一行
            }
            file.close(); // 关闭文件
            std::cout << "Data exported to file: " <<file_name<< std::endl;
        } else {
            std::cout << "Failed to open the output file." << std::endl;
        }
#endif
    }


    void print(uint64_t cli_id,uint64_t coro_id){
#ifdef USE_SUM_COST
        printf("merge_cnt:%ld, merge_time:%lf, split_cnt:%ld, split_time:%lf, insert_time:%lf\n",merge_cnt,merge_time,split_cnt,split_time,insert_time);
        
        std::string insert_file_name = "insert_lat" + std::to_string(cli_id) + std::to_string(coro_id)+".txt";
        to_file(insert_file_name.c_str(),retry_cnt);
        std::string search_file_name = "search_lat" + std::to_string(cli_id) + std::to_string(coro_id)+".txt";
        to_file(search_file_name.c_str(),level_cnt);
#endif
    }

};