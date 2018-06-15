#include "sha256_hash.hpp"
#include <algorithm>
#include <cstring>

static const uint32_t k[64] =
{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2
};

static inline uint32_t rtr(uint32_t x, size_t c)
{
    return (x >> c) | (x << (32 - c));
}

static inline uint32_t rtl(uint32_t x, size_t c)
{
    return (x << c) | (x >> (32 - c));
}

void Sha256Hash::process()
{
    // Populate state
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    // Populate message
    uint32_t w[64];
    for (size_t i = 0U; i < 16U; ++i)
    {
        w[i] = (buffer[i * 4    ] << 24) |
               (buffer[i * 4 + 1] << 16) |
               (buffer[i * 4 + 2] <<  8) |
               (buffer[i * 4 + 3]      );
    }

    // Extend message words
    for (size_t i = 16U; i < 64U; ++i)
    {
        uint32_t s0 = rtr(w[i - 15], 7) ^ rtr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rtr(w[i - 2], 17) ^ rtr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    // Process loop
    for (size_t i = 0U; i < 64U; ++i)
    {
        uint32_t s1 = rtr(e, 6) ^ rtr(e, 11) ^ rtr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t tmp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rtr(a, 2) ^ rtr(a, 13) ^ rtr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t tmp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    // Update the state vector
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

Sha256Hash::Sha256Hash()
{
    clear();
}

void Sha256Hash::clear()
{
    // Seed the state vector
    state[0] = 0x6a09e667U;
    state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U;
    state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU;
    state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU;
    state[7] = 0x5be0cd19U;

    // Clear buffer and total lengths
    buflen = 0U;
    totlen = 0U;
}

void Sha256Hash::add(const void *data, size_t size)
{
    // Loop through the user provided data
    while (size)
    {
        // Calculate how much data to use on this pass
        size_t use = std::min(64U - buflen, size);

        // Copy the data into the buffer
        std::memcpy(buffer + buflen, data, use);

        // Update the pointers, counters and accumulators
        data = static_cast<const uint8_t*>(data) + use;
        size -= use;
        buflen += use;
        totlen += use * 8U;

        // If we've accumulated a full block then process
        if (buflen == 64U)
        {
            buflen = 0U;
            process();
        }
    }
}

std::vector<uint8_t> Sha256Hash::close()
{
    // Save original length
    uint64_t len = totlen;

    // Pad buffer
    static const uint8_t pad[] =
    {
        0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    };

    // Add padding
    size_t padlen = ((buflen < 56U) ? 56U : 120U) - buflen;
    add(pad, padlen);

    // Add length
    uint8_t bitlen[] =
    {
        static_cast<uint8_t>(len >> 56),
        static_cast<uint8_t>(len >> 48),
        static_cast<uint8_t>(len >> 40),
        static_cast<uint8_t>(len >> 32),
        static_cast<uint8_t>(len >> 24),
        static_cast<uint8_t>(len >> 16),
        static_cast<uint8_t>(len >> 8),
        static_cast<uint8_t>(len),
    };
    add(bitlen, 8U);

    // Return the digest
    return {
        static_cast<uint8_t>(state[0] >> 24),
        static_cast<uint8_t>(state[0] >> 16),
        static_cast<uint8_t>(state[0] >> 8),
        static_cast<uint8_t>(state[0]),
        static_cast<uint8_t>(state[1] >> 24),
        static_cast<uint8_t>(state[1] >> 16),
        static_cast<uint8_t>(state[1] >> 8),
        static_cast<uint8_t>(state[1]),
        static_cast<uint8_t>(state[2] >> 24),
        static_cast<uint8_t>(state[2] >> 16),
        static_cast<uint8_t>(state[2] >> 8),
        static_cast<uint8_t>(state[2]),
        static_cast<uint8_t>(state[3] >> 24),
        static_cast<uint8_t>(state[3] >> 16),
        static_cast<uint8_t>(state[3] >> 8),
        static_cast<uint8_t>(state[3]),
        static_cast<uint8_t>(state[4] >> 24),
        static_cast<uint8_t>(state[4] >> 16),
        static_cast<uint8_t>(state[4] >> 8),
        static_cast<uint8_t>(state[4]),
        static_cast<uint8_t>(state[5] >> 24),
        static_cast<uint8_t>(state[5] >> 16),
        static_cast<uint8_t>(state[5] >> 8),
        static_cast<uint8_t>(state[5]),
        static_cast<uint8_t>(state[6] >> 24),
        static_cast<uint8_t>(state[6] >> 16),
        static_cast<uint8_t>(state[6] >> 8),
        static_cast<uint8_t>(state[6]),
        static_cast<uint8_t>(state[7] >> 24),
        static_cast<uint8_t>(state[7] >> 16),
        static_cast<uint8_t>(state[7] >> 8),
        static_cast<uint8_t>(state[7]),
    };
}
