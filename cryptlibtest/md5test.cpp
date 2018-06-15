#include "CppUnitTest.h"
#include "md5_hash.hpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace cryptlibtest
{		
	TEST_CLASS(Md5Test)
	{
	public:
		
		TEST_METHOD(Md5TestEmpty)
		{
            Md5Hash hash;
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0xd4U, 0x1dU, 0x8cU, 0xd9U,
                0x8fU, 0x00U, 0xb2U, 0x04U,
                0xe9U, 0x80U, 0x09U, 0x98U,
                0xecU, 0xf8U, 0x42U, 0x7eU
            };

            Assert::IsTrue(expected == digest);
		}

        TEST_METHOD(Md5Fox)
        {
            Md5Hash hash;
            hash.add("The quick brown fox jumps over the lazy dog", 43U);
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0x9eU, 0x10U, 0x7dU, 0x9dU,
                0x37U, 0x2bU, 0xb6U, 0x82U,
                0x6bU, 0xd8U, 0x1dU, 0x35U,
                0x42U, 0xa4U, 0x19U, 0xd6U
            };

            Assert::IsTrue(expected == digest);
        }
	};
}