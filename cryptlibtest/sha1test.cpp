#include "CppUnitTest.h"
#include "sha1_hash.hpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace cryptlibtest
{
    TEST_CLASS(Sha1Test)
    {
    public:

        TEST_METHOD(Sha1TestEmpty)
        {
            Sha1Hash hash;
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0xdaU, 0x39U, 0xa3U, 0xeeU,
                0x5eU, 0x6bU, 0x4bU, 0x0dU,
                0x32U, 0x55U, 0xbfU, 0xefU,
                0x95U, 0x60U, 0x18U, 0x90U,
                0xafU, 0xd8U, 0x07U, 0x09U
            };

            Assert::IsTrue(expected == digest);
        }

        TEST_METHOD(Sha1Fox)
        {
            Sha1Hash hash;
            hash.add("The quick brown fox jumps over the lazy dog", 43U);
            auto digest = hash.close();

            const std::vector<uint8_t> expected = {
                0x2fU, 0xd4U, 0xe1U, 0xc6U,
                0x7aU, 0x2dU, 0x28U, 0xfcU,
                0xedU, 0x84U, 0x9eU, 0xe1U,
                0xbbU, 0x76U, 0xe7U, 0x39U,
                0x1bU, 0x93U, 0xebU, 0x12U
            };

            Assert::IsTrue(expected == digest);
        }
    };
}