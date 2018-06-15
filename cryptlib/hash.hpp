#pragma once

#include <cstdint>
#include <vector>

/// Hash interface.
class Hash
{
public:
	/// Clear the hash to an initial state.
	virtual void clear() = 0;

	/// Add data to the hash.
	/// @param data                     Pointer to the data to add
    /// @param size                     Size of the data to add
	virtual void add(const void *data, size_t size) = 0;

    /// Close the hash and calculate the digest.
    /// @return                         Message digest
	virtual std::vector<uint8_t> close() = 0;
};