#include "md5_hash.hpp"
#include <algorithm>
#include <cstring>

// Per round shift table.
static const size_t s[64] = 
{
     7U, 12U, 17U, 22U,  7U, 12U, 17U, 22U,  7U, 12U, 17U, 22U,  7U, 12U, 17U, 22U,
     5U,  9U, 14U, 20U,  5U,  9U, 14U, 20U,  5U,  9U, 14U, 20U,  5U,  9U, 14U, 20U,
     4U, 11U, 16U, 23U,  4U, 11U, 16U, 23U,  4U, 11U, 16U, 23U,  4U, 11U, 16U, 23U,
     6U, 10U, 15U, 21U,  6U, 10U, 15U, 21U,  6U, 10U, 15U, 21U,  6U, 10U, 15U, 21U,
};

// Key schedule table (binary integer part of sines of integers).
static const uint32_t k[64] = 
{
    0xD76AA478U, 0xE8C7B756U, 0x242070DBU, 0xC1BDCEEEU,
    0xF57C0FAFU, 0x4787C62AU, 0xA8304613U, 0xFD469501U,
    0x698098D8U, 0x8B44F7AFU, 0xFFFF5BB1U, 0x895CD7BEU,
    0x6B901122U, 0xFD987193U, 0xA679438EU, 0x49B40821U,
    0xF61E2562U, 0xC040B340U, 0x265E5A51U, 0xE9B6C7AAU,
    0xD62F105DU, 0x02441453U, 0xD8A1E681U, 0xE7D3FBC8U,
    0x21E1CDE6U, 0xC33707D6U, 0xF4D50D87U, 0x455A14EDU,
    0xA9E3E905U, 0xFCEFA3F8U, 0x676F02D9U, 0x8D2A4C8AU,
    0xFFFA3942U, 0x8771F681U, 0x6D9D6122U, 0xFDE5380CU,
    0xA4BEEA44U, 0x4BDECFA9U, 0xF6BB4B60U, 0xBEBFBC70U,
    0x289B7EC6U, 0xEAA127FAU, 0xD4EF3085U, 0x04881D05U,
    0xD9D4D039U, 0xE6DB99E5U, 0x1FA27CF8U, 0xC4AC5665U,
    0xF4292244U, 0x432AFF97U, 0xAB9423A7U, 0xFC93A039U,
    0x655B59C3U, 0x8F0CCC92U, 0xFFEFF47DU, 0x85845DD1U,
    0x6FA87E4FU, 0xFE2CE6E0U, 0xA3014314U, 0x4E0811A1U,
    0xF7537E82U, 0xBD3AF235U, 0x2AD7D2BBU, 0xEB86D391U
};

static inline uint32_t rtl(uint32_t x, size_t c)
{
    return (x << c) | (x >> (32 - c));
}

void Md5Hash::process()
{
    // Populate state
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    // Populate message
    uint32_t m[16];
    for (size_t i = 0U; i < 16U; ++i)
    {
        m[i] = (buffer[i * 4    ]      ) | 
               (buffer[i * 4 + 1] <<  8) | 
               (buffer[i * 4 + 2] << 16) |
               (buffer[i * 4 + 3] << 24);
    }

    // Process loop
    for (size_t i = 0U; i < 64U; ++i)
    {
        uint32_t f;
        uint32_t g;
        if (i < 16U)
        {
            f = (b & c) | (~b & d);
            g = i;
        }
        else if (i < 32U)
        {
            f = (d & b) | (~d & c);
            g = (5U * i + 1) & 15U;
        }
        else if (i < 48U)
        {
            f = b ^ c ^ d;
            g = (3U * i + 5) & 15U;
        }
        else
        {
            f = c ^ (b | ~d);
            g = (7U * i) & 15U;
        }

        f = f + a + k[i] + m[g];
        a = d;
        d = c;
        c = b;
        b = b + rtl(f, s[i]);
    }

    // Update the state vector
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

Md5Hash::Md5Hash()
{
    clear();
}

void Md5Hash::clear()
{
    // Seed the state vector
    state[0] = 0x67452301U;
    state[1] = 0xEFCDAB89U;
    state[2] = 0x98BADCFEU;
    state[3] = 0x10325476U;

    // Clear buffer and total lengths
    buflen = 0U;
    totlen = 0U;
}

void Md5Hash::add(const void *data, size_t size)
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

std::vector<uint8_t> Md5Hash::close()
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
        static_cast<uint8_t>(len),
        static_cast<uint8_t>(len >> 8),
        static_cast<uint8_t>(len >> 16),
        static_cast<uint8_t>(len >> 24),
        static_cast<uint8_t>(len >> 32),
        static_cast<uint8_t>(len >> 40),
        static_cast<uint8_t>(len >> 48),
        static_cast<uint8_t>(len >> 56),
    };
    add(bitlen, 8U);

    // Return the digest
    return {
        static_cast<uint8_t>(state[0]),
        static_cast<uint8_t>(state[0] >> 8),
        static_cast<uint8_t>(state[0] >> 16),
        static_cast<uint8_t>(state[0] >> 24),
        static_cast<uint8_t>(state[1]),
        static_cast<uint8_t>(state[1] >> 8),
        static_cast<uint8_t>(state[1] >> 16),
        static_cast<uint8_t>(state[1] >> 24),
        static_cast<uint8_t>(state[2]),
        static_cast<uint8_t>(state[2] >> 8),
        static_cast<uint8_t>(state[2] >> 16),
        static_cast<uint8_t>(state[2] >> 24),
        static_cast<uint8_t>(state[3]),
        static_cast<uint8_t>(state[3] >> 8),
        static_cast<uint8_t>(state[3] >> 16),
        static_cast<uint8_t>(state[3] >> 24),
    };
}
