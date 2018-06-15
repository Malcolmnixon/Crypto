#include "md5.h"
#include <stdint.h>


/// MD5 State structure
struct MD5State
{
	/// State words
	uint32_t s[4];

	/// Block buffer
	uint8_t b[64];
};