// Copyright (c) 2013-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "consensus/validation.h"
#include "main.h" // For CheckBlock
#include "primitives/block.h"
#include "test/test_bitcoin.h"
#include "utiltime.h"
#include "validation/validation.h"

#include <cstdio>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/test/unit_test.hpp>

bool read_block(const std::string &filename, CBlock &block)
{
    namespace fs = boost::filesystem;
    fs::path testFile = fs::current_path() / "data" / filename;
#ifdef TEST_DATA_DIR
    if (!fs::exists(testFile))
    {
        testFile = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
    }
#endif
    FILE *fp = fopen(testFile.string().c_str(), "rb");
    if (!fp)
        return false;

    fseek(fp, 8, SEEK_SET); // skip msgheader/size

    CAutoFile filein(fp, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return false;

    filein >> block;
    return true;
}

bool LockAndContextualCheckBlock(CBlock &block, CValidationState &state)
{
    LOCK(cs_main);
    return ContextualCheckBlock(block, state, nullptr);
}

BOOST_FIXTURE_TEST_SUITE(checkblock_tests, BasicTestingSetup) // BU harmonize suite name with filename


BOOST_AUTO_TEST_CASE(TestBlock)
{
#if 0 // TODO: removed until we get block format solidifies
    CBlock testblock;
    bool fReadBlock = read_block("testblock.dat", testblock);
    BOOST_CHECK_MESSAGE(fReadBlock, "Failed to read testblock.dat");
    if (fReadBlock)
    {
        CValidationState state;
        BOOST_CHECK_MESSAGE(CheckBlock(testblock, state, false, false), "Basic CheckBlock failed");
        BOOST_CHECK_MESSAGE(LockAndContextualCheckBlock(testblock, state), "Contextual CheckBlock failed");
    }
#endif
}

BOOST_AUTO_TEST_SUITE_END()
