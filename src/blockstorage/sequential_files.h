// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_SEQUENTIAL_H
#define BLOCKDB_SEQUENTIAL_H

#include "net.h"
#include "txdb.h"
#include "undo.h"
#include "validationinterface.h"

#include <set>
#include <stdint.h>


/** Access to the block database (blocks/ * /) */
class CBlockFileDB : public CDatabaseAbstract
{
public:
    CBlockFileDB() {}

private:
    CBlockFileDB(const CBlockFileDB &);
    void operator=(const CBlockFileDB &);

public:
    ~CBlockFileDB() {}

    bool WriteBlock(const CBlock &block, CDiskBlockPos &pos);
    bool WriteBlock(const CTailstormBlock &block, CDiskBlockPos &pos);

    bool ReadBlock(const CBlockIndex *pindex, CBlock &block);
    bool ReadBlock(const CBlockIndex *pindex, CTailstormBlock &block);

    bool EraseBlock(CBlock &block);
    bool EraseBlock(CTailstormBlock &block);
    bool EraseBlock(const CBlockIndex *pindex);

    void Flush(bool fFinalize = false);

    void CondenseBlockData(const std::string &key_begin, const std::string &key_end)
    {
        // intentionally left blank
    }

    bool WriteUndo(const CBlockUndo &blockundo, const CBlockIndex *pindex, CDiskBlockPos &pos);
    bool ReadUndo(CBlockUndo &blockundo, const CBlockIndex *pindex, const CDiskBlockPos &pos);
    bool EraseUndo(const CBlockIndex *pindex);

    void CondenseUndoData(const std::string &key_begin, const std::string &key_end)
    {
        // intentionally left blank
    }

    uint64_t PruneDB(std::set<int> &setFilesToPrune, uint64_t nLastBlockWeCanPrune);
};

/** Open a block file (blk?????.dat) */
FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(std::set<int> &setFilesToPrune);

/** Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage();

#endif // BLOCKDB_SEQUENTIAL_H
