#include "sha1_hash.hpp"
#include <algorithm>
#include <cstring>

static inline uint32_t rtl(uint32_t x, size_t c)
{
    return (x << c) | (x >> (32 - c));
}

void Sha1Hash::process()
{
    // Populate state
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];

    // Populate message
    uint32_t w[80];
    for (size_t i = 0U; i < 16U; ++i)
    {
        w[i] = (buffer[i * 4    ] << 24) |
               (buffer[i * 4 + 1] << 16) |
               (buffer[i * 4 + 2] <<  8) |
               (buffer[i * 4 + 3]      );
    }

    // Extend message words
    for (size_t i = 16U; i < 80U; ++i)
    {
        w[i] = rtl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1U);
    }

    // Process loop
    for (size_t i = 0U; i < 80U; ++i)
    {
        uint32_t f;
        uint32_t k;
        if (i < 20U)
        {
            f = (b & c) | (~b & d);
            k = 0x5A827999U;
        }
        else if (i < 40U)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        }
        else if (i < 60U)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }

        uint32_t tmp = rtl(a, 5U) + f + e + k + w[i];
        e = d;
        d = c;
        c = rtl(b, 30U);
        b = a;
        a = tmp;
    }

    // Update the state vector
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

Sha1Hash::Sha1Hash()
{
    clear();
}

void Sha1Hash::clear()
{
    // Seed the state vector
    state[0] = 0x67452301U;
    state[1] = 0xEFCDAB89U;
    state[2] = 0x98BADCFEU;
    state[3] = 0x10325476U;
    state[4] = 0xC3D2E1F0U;

    // Clear buffer and total lengths
    buflen = 0U;
    totlen = 0U;
}

void Sha1Hash::add(const void *data, size_t size)
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

std::vector<uint8_t> Sha1Hash::close()
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
    };
}
