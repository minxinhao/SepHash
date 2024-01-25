#include <functional>
#include <tuple>
#include "hash.h"


std::tuple<uint64_t, uint64_t> cal_single_filter(uint64_t pattern,uint64_t* filter_data){
  uint64_t size = 128;
  uint64_t pos = pattern >> 56;
  pos %= size;
  uint64_t filter_id = pos / 64;
  return std::make_tuple(filter_id,(1ULL << (pos % 64)));
}


/// @brief 鉴于多hash函数的bloomfilter过滤效果太差,这里使用单个filter进行过滤
/// @param pattern 直接使用key生产的pattern的高8位选择对应的bits（前面没使用过）
/// @param size filter_data的数量（64/128/256） 
/// @param filter_data 
void single_hash_filter(uint64_t pattern,uint64_t size,uint64_t* filter_data){
  uint64_t pos = pattern >> 56;
  pos %= size;
  uint64_t filter_id = pos / 64;
  filter_data[filter_id] |= (1ULL << (pos % 64));
}

bool check_single_hash_filter(uint64_t pattern,uint64_t size,uint64_t* filter_data){
  uint64_t len = size/64;
  // printf("filter(%lu): ",size);
  // for(uint64_t i = 0 ; i < len ; i++){
  //   printf("%16lx ",filter_data[i]);
  // }
  // printf("\n");
  uint64_t pos = pattern >> 56;
  pos %= size;
  uint64_t filter_id = pos / 64;
  uint64_t filter_pos = 1ull << (pos % 64);
  // printf("filter_data[%lu]:%lx filter_pos:%lx res:%lu\n",filter_id,filter_data[filter_id],filter_pos,(filter_data[filter_id] & filter_pos));
  return (filter_data[filter_id] & filter_pos);
}

std::tuple<uint64_t, uint64_t> cal_filter(const uint32_t hash, uint64_t id)
{
    // //Source:
    // https://github.com/FastFilter/fastfilter_cpp/blob/master/src/bloom/simd-block.h
    // 这部分开销很小，为了避免部署环境麻烦直接把SIMD换成普通指令了
    uint32_t ones[4] = {1, 1, 1, 1};
    uint32_t rehash_1[4] = {0x47b6137bU, 0x44974d91U, 0x8824ad5bU, 0xa2b7289dU};
    uint32_t rehash_2[4] = {0x705495c7U, 0x2df1424bU, 0x9efc4947U, 0x5c6bfb31U};
    uint32_t hash_data[4] = {hash, hash, hash, hash};
    uint32_t *rehash = (id == 1) ? rehash_1 : rehash_2;
    hash_data[0] = rehash[0] * hash_data[0];
    hash_data[1] = rehash[1] * hash_data[1];
    hash_data[2] = rehash[2] * hash_data[2];
    hash_data[3] = rehash[3] * hash_data[3];
    hash_data[0] = hash_data[0] >> 27;
    hash_data[1] = hash_data[1] >> 27;
    hash_data[2] = hash_data[2] >> 27;
    hash_data[3] = hash_data[3] >> 27;
    ones[0] = ones[0] << hash_data[0];
    ones[1] = ones[1] << hash_data[1];
    ones[2] = ones[2] << hash_data[2];
    ones[3] = ones[3] << hash_data[3];
    uint64_t res_1 = ones[3];
    res_1 = res_1 << 32;
    res_1 |= ones[2];
    uint64_t res_2 = ones[1];
    res_2 = res_2 << 32;
    res_2 |= ones[0];
    return std::make_tuple(res_1, res_2);
}


size_t standard(const void* _ptr, size_t _len,size_t _seed=static_cast<size_t>(0xc70f6907UL));
size_t jenkins(const void* _ptr, size_t _len, size_t _seed=0xc70f6907UL);
size_t murmur2 ( const void * key, size_t len, size_t seed=0xc70f6907UL);
std::tuple<uint64_t,uint64_t> murmur3(const void *key, const int len, const uint32_t seed=0xc70f6907UL);
uint64_t xxhash(const void *data, size_t length, size_t seed=0xc70f6907UL);



size_t hash_1(const void* _ptr, size_t _len){
    // return std::get<0>(murmur3(_ptr,_len));
    return xxhash(_ptr,_len);
    // return murmur2(_ptr,_len); //测试发现这个函数有问题
}

size_t hash_2(const void* _ptr, size_t _len){
    // return std::get<1>(murmur3(_ptr,_len));
    // return jenkins(_ptr,_len);
    return standard(_ptr,_len);
}

size_t standard(const void* _ptr, size_t _len,
                        size_t _seed){
    return std::_Hash_bytes(_ptr, _len, _seed);
}

// JENKINS HASH FUNCTION
size_t jenkins(const void* _ptr, size_t _len, size_t _seed){
    size_t i = 0;
    size_t hash = 0;
    const char* key = static_cast<const char*>(_ptr);
    while (i != _len) {
        hash += key[i++];
        hash += hash << (10);
        hash ^= hash >> (6);
    }
    hash += hash << (3);
    hash ^= hash >> (11);
    hash += hash << (15);
    return hash;
}


//-----------------------------------------------------------------------------
// MurmurHash2, by Austin Appleby

// Note - This code makes a few assumptions about how your machine behaves -

// 1. We can read a 4-byte value from any address without crashing
// 2. sizeof(int) == 4

// And it has a few limitations -

// 1. It will not work incrementally.
// 2. It will not produce the same results on little-endian and big-endian
//    machines.
size_t murmur2 ( const void * key, size_t len, size_t seed)
{
    // 'm' and 'r' are mixing constants generated offline.
    // They're not really 'magic', they just happen to work well.

    const unsigned int m = 0x5bd1e995;
    const int r = 24;

    // Initialize the hash to a 'random' value

    unsigned int h = seed ^ len;

    // Mix 4 bytes at a time into the hash

    const unsigned char * data = (const unsigned char *)key;

    while(len >= 4)
    {
        unsigned int k = *(unsigned int *)data;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    // Handle the last few bytes of the input array

    switch(len)
    {
        case 3: h ^= data[2] << 16;
        case 2: h ^= data[1] << 8;
        case 1: h ^= data[0];
            h *= m;
    };

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}

#define NUMBER64_1 11400714785074694791ULL
#define NUMBER64_2 14029467366897019727ULL
#define NUMBER64_3 1609587929392839161ULL
#define NUMBER64_4 9650029242287828579ULL
#define NUMBER64_5 2870177450012600261ULL

#define hash_get64bits(x) hash_read64_align(x, align)
#define hash_get32bits(x) hash_read32_align(x, align)
#define shifting_hash(x, r) ((x << r) | (x >> (64 - r)))
#define TO64(x) (((U64_INT *)(x))->v)
#define TO32(x) (((U32_INT *)(x))->v)


typedef struct U64_INT
{
    uint64_t v;
} U64_INT;

typedef struct U32_INT
{
    uint32_t v;
} U32_INT;

uint64_t hash_read64_align(const void *ptr, uint32_t align)
{
    if (align == 0)
    {
        return TO64(ptr);
    }
    return *(uint64_t *)ptr;
}

uint32_t hash_read32_align(const void *ptr, uint32_t align)
{
    if (align == 0)
    {
        return TO32(ptr);
    }
    return *(uint32_t *)ptr;
}

uint64_t hash_compute(const void *input, uint64_t length, uint64_t seed, uint32_t align)
{
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + length;
    uint64_t hash;

    if (length >= 32)
    {
        const uint8_t *const limitation = end - 32;
        uint64_t v1 = seed + NUMBER64_1 + NUMBER64_2;
        uint64_t v2 = seed + NUMBER64_2;
        uint64_t v3 = seed + 0;
        uint64_t v4 = seed - NUMBER64_1;

        do
        {
            v1 += hash_get64bits(p) * NUMBER64_2;
            p += 8;
            v1 = shifting_hash(v1, 31);
            v1 *= NUMBER64_1;
            v2 += hash_get64bits(p) * NUMBER64_2;
            p += 8;
            v2 = shifting_hash(v2, 31);
            v2 *= NUMBER64_1;
            v3 += hash_get64bits(p) * NUMBER64_2;
            p += 8;
            v3 = shifting_hash(v3, 31);
            v3 *= NUMBER64_1;
            v4 += hash_get64bits(p) * NUMBER64_2;
            p += 8;
            v4 = shifting_hash(v4, 31);
            v4 *= NUMBER64_1;
        } while (p <= limitation);

        hash = shifting_hash(v1, 1) + shifting_hash(v2, 7) + shifting_hash(v3, 12) + shifting_hash(v4, 18);

        v1 *= NUMBER64_2;
        v1 = shifting_hash(v1, 31);
        v1 *= NUMBER64_1;
        hash ^= v1;
        hash = hash * NUMBER64_1 + NUMBER64_4;

        v2 *= NUMBER64_2;
        v2 = shifting_hash(v2, 31);
        v2 *= NUMBER64_1;
        hash ^= v2;
        hash = hash * NUMBER64_1 + NUMBER64_4;

        v3 *= NUMBER64_2;
        v3 = shifting_hash(v3, 31);
        v3 *= NUMBER64_1;
        hash ^= v3;
        hash = hash * NUMBER64_1 + NUMBER64_4;

        v4 *= NUMBER64_2;
        v4 = shifting_hash(v4, 31);
        v4 *= NUMBER64_1;
        hash ^= v4;
        hash = hash * NUMBER64_1 + NUMBER64_4;
    }
    else
    {
        hash = seed + NUMBER64_5;
    }

    hash += (uint64_t)length;

    while (p + 8 <= end)
    {
        uint64_t k1 = hash_get64bits(p);
        k1 *= NUMBER64_2;
        k1 = shifting_hash(k1, 31);
        k1 *= NUMBER64_1;
        hash ^= k1;
        hash = shifting_hash(hash, 27) * NUMBER64_1 + NUMBER64_4;
        p += 8;
    }

    if (p + 4 <= end)
    {
        hash ^= (uint64_t)(hash_get32bits(p)) * NUMBER64_1;
        hash = shifting_hash(hash, 23) * NUMBER64_2 + NUMBER64_3;
        p += 4;
    }

    while (p < end)
    {
        hash ^= (*p) * NUMBER64_5;
        hash = shifting_hash(hash, 11) * NUMBER64_1;
        p++;
    }

    hash ^= hash >> 33;
    hash *= NUMBER64_2;
    hash ^= hash >> 29;
    hash *= NUMBER64_3;
    hash ^= hash >> 32;

    return hash;
}

uint64_t xxhash(const void *data, size_t length, size_t seed)
{
    if ((((uint64_t)data) & 7) == 0)
    {
        return hash_compute(data, length, seed, 1);
    }
    return hash_compute(data, length, seed, 0);
}


#ifdef __GNUC__
#define FORCE_INLINE __attribute__((always_inline)) inline
#else
#define FORCE_INLINE inline
#endif

static FORCE_INLINE uint32_t rotl32(uint32_t x, int8_t r)
{
  return (x << r) | (x >> (32 - r));
}

static FORCE_INLINE uint64_t rotl64(uint64_t x, int8_t r)
{
  return (x << r) | (x >> (64 - r));
}

#define ROTL32(x, y) rotl32(x, y)
#define ROTL64(x, y) rotl64(x, y)

#define BIG_CONSTANT(x) (x##LLU)

#define getblock(p, i) (p[i])

static FORCE_INLINE uint64_t fmix64(uint64_t k)
{
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xff51afd7ed558ccd);
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
  k ^= k >> 33;

  return k;
}

// murmur3 hash
std::tuple<uint64_t,uint64_t> murmur3(const void *key, const int len, const uint32_t seed)
{
  const uint8_t *data = (const uint8_t *)key;
  const int nblocks = len / 16;
  int i;

  uint64_t h1 = seed;
  uint64_t h2 = seed;

  uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
  uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

  //----------
  // body

  const uint64_t *blocks = (const uint64_t *)(data);

  for (i = 0; i < nblocks; i++)
  {
    uint64_t k1 = getblock(blocks, i * 2 + 0);
    uint64_t k2 = getblock(blocks, i * 2 + 1);

    k1 *= c1;
    k1 = ROTL64(k1, 31);
    k1 *= c2;
    h1 ^= k1;

    h1 = ROTL64(h1, 27);
    h1 += h2;
    h1 = h1 * 5 + 0x52dce729;

    k2 *= c2;
    k2 = ROTL64(k2, 33);
    k2 *= c1;
    h2 ^= k2;

    h2 = ROTL64(h2, 31);
    h2 += h1;
    h2 = h2 * 5 + 0x38495ab5;
  }

  //----------
  // tail

  const uint8_t *tail = (const uint8_t *)(data + nblocks * 16);

  uint64_t k1 = 0;
  uint64_t k2 = 0;

  switch (len & 15)
  {
  case 15:
    k2 ^= (uint64_t)(tail[14]) << 48;
  case 14:
    k2 ^= (uint64_t)(tail[13]) << 40;
  case 13:
    k2 ^= (uint64_t)(tail[12]) << 32;
  case 12:
    k2 ^= (uint64_t)(tail[11]) << 24;
  case 11:
    k2 ^= (uint64_t)(tail[10]) << 16;
  case 10:
    k2 ^= (uint64_t)(tail[9]) << 8;
  case 9:
    k2 ^= (uint64_t)(tail[8]) << 0;
    k2 *= c2;
    k2 = ROTL64(k2, 33);
    k2 *= c1;
    h2 ^= k2;

  case 8:
    k1 ^= (uint64_t)(tail[7]) << 56;
  case 7:
    k1 ^= (uint64_t)(tail[6]) << 48;
  case 6:
    k1 ^= (uint64_t)(tail[5]) << 40;
  case 5:
    k1 ^= (uint64_t)(tail[4]) << 32;
  case 4:
    k1 ^= (uint64_t)(tail[3]) << 24;
  case 3:
    k1 ^= (uint64_t)(tail[2]) << 16;
  case 2:
    k1 ^= (uint64_t)(tail[1]) << 8;
  case 1:
    k1 ^= (uint64_t)(tail[0]) << 0;
    k1 *= c1;
    k1 = ROTL64(k1, 31);
    k1 *= c2;
    h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;
  h2 ^= len;

  h1 += h2;
  h2 += h1;

  h1 = fmix64(h1);
  h2 = fmix64(h2);

  h1 += h2;
  h2 += h1;
  // h1 += h1 == h2 ? 0x125e591ull : 0ull;

  return std::make_tuple(h1, h2);
// return h1;
}

// murmur3 hash
__uint128_t hash(const void *key, const int len, const uint32_t seed) noexcept
{
  const uint8_t *data = (const uint8_t *)key;
  const int nblocks = len / 16;
  int i;

  uint64_t h1 = seed;
  uint64_t h2 = seed;

  uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
  uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

  //----------
  // body

  const uint64_t *blocks = (const uint64_t *)(data);

  for (i = 0; i < nblocks; i++)
  {
    uint64_t k1 = getblock(blocks, i * 2 + 0);
    uint64_t k2 = getblock(blocks, i * 2 + 1);

    k1 *= c1;
    k1 = ROTL64(k1, 31);
    k1 *= c2;
    h1 ^= k1;

    h1 = ROTL64(h1, 27);
    h1 += h2;
    h1 = h1 * 5 + 0x52dce729;

    k2 *= c2;
    k2 = ROTL64(k2, 33);
    k2 *= c1;
    h2 ^= k2;

    h2 = ROTL64(h2, 31);
    h2 += h1;
    h2 = h2 * 5 + 0x38495ab5;
  }

  //----------
  // tail

  const uint8_t *tail = (const uint8_t *)(data + nblocks * 16);

  uint64_t k1 = 0;
  uint64_t k2 = 0;

  switch (len & 15)
  {
  case 15:
    k2 ^= (uint64_t)(tail[14]) << 48;
  case 14:
    k2 ^= (uint64_t)(tail[13]) << 40;
  case 13:
    k2 ^= (uint64_t)(tail[12]) << 32;
  case 12:
    k2 ^= (uint64_t)(tail[11]) << 24;
  case 11:
    k2 ^= (uint64_t)(tail[10]) << 16;
  case 10:
    k2 ^= (uint64_t)(tail[9]) << 8;
  case 9:
    k2 ^= (uint64_t)(tail[8]) << 0;
    k2 *= c2;
    k2 = ROTL64(k2, 33);
    k2 *= c1;
    h2 ^= k2;

  case 8:
    k1 ^= (uint64_t)(tail[7]) << 56;
  case 7:
    k1 ^= (uint64_t)(tail[6]) << 48;
  case 6:
    k1 ^= (uint64_t)(tail[5]) << 40;
  case 5:
    k1 ^= (uint64_t)(tail[4]) << 32;
  case 4:
    k1 ^= (uint64_t)(tail[3]) << 24;
  case 3:
    k1 ^= (uint64_t)(tail[2]) << 16;
  case 2:
    k1 ^= (uint64_t)(tail[1]) << 8;
  case 1:
    k1 ^= (uint64_t)(tail[0]) << 0;
    k1 *= c1;
    k1 = ROTL64(k1, 31);
    k1 *= c2;
    h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;
  h2 ^= len;

  h1 += h2;
  h2 += h1;

  h1 = fmix64(h1);
  h2 = fmix64(h2);

  h1 += h2;
  h2 += h1;
  // h1 += h1 == h2 ? 0x125e591ull : 0ull;

  return (__uint128_t)h1 << 64 | h2;
}