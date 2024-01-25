#pragma once
#include <stdint.h>
#include <cmath>
#include <random>

class Generator
{
public:
    virtual uint64_t operator()(double u) = 0;
};

inline uint64_t rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

class splitmix64
{
    uint64_t state;

public:
    splitmix64(uint64_t seed = 536873221) : state(seed) {}
    inline uint64_t operator()()
    {
        uint64_t z = (state += UINT64_C(0x9E3779B97F4A7C15));
        z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
        return z ^ (z >> 31);
    }
};

/// @brief Random Generator
class xoshiro256pp
{
    uint64_t state[4];

public:
    const uint64_t jump128[4] = {0x180ec6d33cfd0aba, 0xd5a61266f0c9392c, 0xa9582618e03fc9aa, 0x39abdc4529b1661c};
    const uint64_t jump192[4] = {0x76e15d3efefdcbbf, 0xc5004e441c522fb3, 0x77710069854ee241, 0x39109bb02acbe635};
    xoshiro256pp(uint64_t seed = 536873221)
    {
        splitmix64 gen(seed);
        for (int i = 0; i < 4; ++i)
            state[i] = gen();
    }
    inline void next_state()
    {
        uint64_t t = state[1] << 17;
        state[2] ^= state[0];
        state[3] ^= state[1];
        state[1] ^= state[2];
        state[0] ^= state[3];
        state[2] ^= t;
        state[3] = rotl(state[3], 45);
    }
    inline uint64_t u64()
    {
        uint64_t result = rotl(state[0] + state[3], 23) + state[0];
        next_state();
        return result;
    }
    /// @brief return random float between [0,1.0]
    /// @return
    inline double f64() { return (u64() >> 11) * 0x1.0p-53; }
    inline double operator()() { return f64(); }
    void jump(const uint64_t *jmp_array = nullptr)
    {
        if (!jmp_array)
            jmp_array = jump128;
        uint64_t new_state[4] = {0};
        for (int i = 0; i < 4; ++i)
            for (int b = 0; b < 64; ++b)
            {
                if (jmp_array[i] & UINT64_C(1) << b)
                    for (int j = 0; j < 4; ++j)
                        new_state[j] ^= state[j];
                next_state();
            }
    }
};

class uniform : public Generator
{
    std::mt19937_64 gen;
    std::uniform_int_distribution<uint64_t> dist;
public:
    uniform(uint64_t items) : dist(0, items - 1) {}
    uint64_t operator()(double u) { 
        return dist(gen);
    }
};

class seq_gen : public Generator
{
    uint64_t items;
    uint64_t cur;

public:
    seq_gen(uint64_t _items) :items{_items},cur{0} {}
    uint64_t operator()(double u) { 
        return cur++;
    }
};


class zipf99 : public Generator
{
    const double theta = .99;
    const double alpha = 1. / (1. - theta);
    const double zeta2theta = zeta(2);
    uint64_t items;
    double zetan;
    double eta;
    constexpr double zeta(uint32_t n)
    {
        double ans = 0.;
        for (uint32_t i = 1; i <= n; ++i)
            ans += pow(1. / i, theta);
        return ans;
    }

public:
    zipf99(uint64_t items) : items(items), zetan(zeta(items))
    {
        eta = (1 - pow(2. / items, 1 - theta)) / (1 - zeta2theta / zetan);
    }
    uint64_t operator()(double u)
    {
        double uz = u * zetan;
        if (uz < 1.)
            return 0;
        if (uz < 1. + pow(.5, theta))
            return 1;
        return items * pow(eta * u - eta + 1, alpha);
    }
};

class SkewedLatestGenerator : public Generator
{
public:
    SkewedLatestGenerator(uint64_t _items) : items(_items), zipfian_(_items)
    {
    }

    uint64_t operator()(double u)
    {
        return items - zipfian_(u);
    }

private:
    uint64_t items;
    zipf99 zipfian_;
};

const uint64_t kFNVOffsetBasis64 = 0xCBF29CE484222325;
const uint64_t kFNVPrime64 = 1099511628211;

inline uint64_t FNVHash64(uint64_t val) {
  uint64_t hash = kFNVOffsetBasis64;

  for (int i = 0; i < 8; i++) {
    uint64_t octet = val & 0x00ff;
    val = val >> 8;

    hash = hash ^ octet;
    hash = hash * kFNVPrime64;
  }
  return hash;
}