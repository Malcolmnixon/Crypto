#pragma once

#include "hash.hpp"

/// SHA256 Hash class.
class Sha256Hash : public Hash
{
    /// SHA256 state vector.
    uint32_t state[8];

    /// SHA256 accumulation buffer.
    uint8_t buffer[64];

    /// SHA256 accumulation boffer length.
    size_t buflen;

    /// SHA256 total bit count
    uint64_t totlen;

    /// Process a full block
    void process();

public:
    /// Constructor.
    Sha256Hash();

    /// Delete copy constructor.
    Sha256Hash(const Sha256Hash &) = delete;

    /// Delete assignment operator.
    Sha256Hash &operator=(const Sha256Hash &) = delete;

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
