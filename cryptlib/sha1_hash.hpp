#pragma once

#include "hash.hpp"

/// SHA1 Hash class.
class Sha1Hash : public Hash
{
    /// SHA1 state vector.
    uint32_t state[5];

    /// SHA1 accumulation buffer.
    uint8_t buffer[64];

    /// SHA1 accumulation boffer length.
    size_t buflen;

    /// SHA1 total bit count
    uint64_t totlen;

    /// Process a full block
    void process();

public:
    /// Constructor.
    Sha1Hash();

    /// Delete copy constructor.
    Sha1Hash(const Sha1Hash &) = delete;

    /// Delete assignment operator.
    Sha1Hash &operator=(const Sha1Hash &) = delete;

    /// Clear the hash to an initial state.
    virtual void clear();

    /// Add data to the hash.
    /// @param data                     Pointer to the data to add
    /// @param size                     Size of the data to add
    virtual void add(const void *data, size_t size);

    /// Close the hash and calculate the digest.
    /// @return                         Message digest
    virtual std::vector<uint8_t> close();
};
