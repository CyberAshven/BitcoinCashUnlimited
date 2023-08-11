// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "arith_uint256.h"
#include "crypto/common.h"
#include "hashwrapper.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "randomx/randomx.h"
#include <iostream>

//uint256 CBlockHeader::GetHash() const { return SerializeHash(*this); }

uint256 CBlockHeader::GetHash() const
{ 
    //Just trying to run the randomx functions in the context of a BU build. 
    
    const char myKey[] = "RandomX example key";
	const char myInput[] = "RandomX example input";
	//char hash[RANDOMX_HASH_SIZE];
    uint256 hash;

    std::cout << "Get flags" << std::endl;
	randomx_flags flags = randomx_get_flags();
    flags=RANDOMX_FLAG_DEFAULT;
    std::cout << flags << std::endl;
    std::cout << "Allocate cache" << std::endl;
    randomx_cache *myCache = randomx_alloc_cache(flags);
	if (myCache == nullptr) {
		std::cout << "Cache allocation failed" << std::endl;
		return SerializeHash(*this);
	}
	
	randomx_init_cache(myCache, &myKey, sizeof myKey);
	randomx_vm *myMachine = randomx_create_vm(flags, myCache, NULL);
	randomx_calculate_hash(myMachine, &myInput, sizeof myInput, &hash);
	randomx_destroy_vm(myMachine);
	randomx_release_cache(myCache);

	//for (unsigned i = 0; i < RANDOMX_HASH_SIZE; ++i)
	//	printf("%02x", hash[i] & 0xff);
	//printf("\n");

	//return hash;
    return SerializeHash(*this);
 }

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

uint64_t CBlock::GetBlockSize() const
{
    if (nBlockSize == 0)
        nBlockSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    return nBlockSize;
}


arith_uint256 GetWorkForDifficultyBits(uint32_t nBits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}
