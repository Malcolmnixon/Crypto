#pragma once

#include "hash.hpp"

/// MD5 Hash class.
class Md5Hash : public Hash
{
    /// MD5 state vector.
	uint32_t state[4];

    /// MD5 accumulation buffer.
	uint8_t buffer[64];

    /// MD5 accumulation boffer length.
    size_t buflen;

    /// MD5 total bit count
    uint64_t totlen;

    /// Process a full block
    void process();

public:
    /// Constructor.
	Md5Hash();

    /// Delete copy constructor.
    Md5Hash(const Md5Hash &) = delete;

    /// Delete assignment operator.
    Md5Hash &operator=(const Md5Hash &) = delete;

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
