#pragma once
#include <stdint.h>
#include <stddef.h>

size_t hash_1(const void* _ptr, size_t _len);
size_t hash_2(const void* _ptr, size_t _len);
__uint128_t hash(const void *key, const int len, const uint32_t seed = 0) noexcept;

void single_hash_filter(uint64_t pattern,uint64_t size,uint64_t* filter_data);
std::tuple<uint64_t, uint64_t> cal_single_filter(uint64_t pattern,uint64_t* filter_data);
bool check_single_hash_filter(uint64_t pattern,uint64_t size,uint64_t* filter_data);
std::tuple<uint64_t, uint64_t> cal_filter(const uint32_t hash, uint64_t id  = 1);