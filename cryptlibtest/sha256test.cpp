#include "CppUnitTest.h"
#include "sha256_hash.hpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace cryptlibtest
{
    TEST_CLASS(Sha256Test)
    {
    public:

        TEST_METHOD(Sha256TestEmpty)
        {
            Sha256Hash hash;
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0xe3U, 0xb0U, 0xc4U, 0x42U,
                0x98U, 0xfcU, 0x1cU, 0x14U,
                0x9aU, 0xfbU, 0xf4U, 0xc8U,
                0x99U, 0x6fU, 0xb9U, 0x24U,
                0x27U, 0xaeU, 0x41U, 0xe4U,
                0x64U, 0x9bU, 0x93U, 0x4cU,
                0xa4U, 0x95U, 0x99U, 0x1bU,
                0x78U, 0x52U, 0xb8U, 0x55U
            };

            Assert::IsTrue(expected == digest);
        }

        TEST_METHOD(Sha256Fox)
        {
            Sha256Hash hash;
            hash.add("The quick brown fox jumps over the lazy dog", 43U);
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0xD7U, 0xA8U, 0xFBU, 0xB3U,
                0x07U, 0xD7U, 0x80U, 0x94U,
                0x69U, 0xCAU, 0x9AU, 0xBCU,
                0xB0U, 0x08U, 0x2EU, 0x4FU,
                0x8DU, 0x56U, 0x51U, 0xE4U,
                0x6DU, 0x3CU, 0xDBU, 0x76U,
                0x2DU, 0x02U, 0xD0U, 0xBFU,
                0x37U, 0xC9U, 0xE5U, 0x92U
            };

            Assert::IsTrue(expected == digest);
        }
    };
}