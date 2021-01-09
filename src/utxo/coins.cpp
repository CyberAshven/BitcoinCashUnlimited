// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utxo/coins.h"

#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "memusage.h"
#include "random.h"
#include "undo.h"
#include "util.h"

#include <assert.h>
bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
bool CCoinsView::HaveCoin(const COutPoint &outpoint) const { return false; }
uint256 CCoinsView::GetBestBlock() const
{
    READLOCK(cs_utxo);
    return uint256();
}
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlock,
    const uint64_t nBestCoinHeight,
    size_t &nChildCachedCoinsUsage)
{
    return false;
}
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }
CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) {}
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlock,
    const uint64_t nBestCoinHeight,
    size_t &nChildCachedCoinsUsage)
{
    return base->BatchWrite(mapCoins, hashBlock, nBestCoinHeight, nChildCachedCoinsUsage);
}
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }
SaltedOutpointHasher::SaltedOutpointHasher()
    : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max()))
{
}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn, uint8_t _num_fragments)
    : CCoinsViewBacked(baseIn), nBestCoinHeight(0), cachedCoinsUsage(0), cacheCoins(_num_fragments)
{
}

size_t CCoinsViewCache::DynamicMemoryUsage() const
{
    size_t nUsage;
    cacheCoins.lock_shared(__FILE__, __LINE__);
    {
        READLOCK(cs_utxo);
        nUsage = cacheCoins.DynamicUsage() + cachedCoinsUsage;
    }
    cacheCoins.unlock_shared();
    return nUsage;
}
size_t CCoinsViewCache::_DynamicMemoryUsage() const { return cacheCoins.DynamicUsage() + cachedCoinsUsage; }
size_t CCoinsViewCache::ResetCachedCoinUsage() const
{
    bool drifted = false;
    size_t newCachedCoinsUsage = 0;
    {
        cacheCoins.lock_shared(__FILE__, __LINE__);
        newCachedCoinsUsage = cacheCoins.CalculateMemoryUsageUsingCoins();
        cacheCoins.unlock_shared();
        drifted = (cachedCoinsUsage != newCachedCoinsUsage);
    }
    if (drifted)
    {
        error(
            "Resetting: cachedCoinsUsage has drifted - before %lld after %lld", cachedCoinsUsage, newCachedCoinsUsage);
        WRITELOCK(cs_utxo);
        cachedCoinsUsage = newCachedCoinsUsage;
    }
    return newCachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::_GetCoinFromCache(const COutPoint &outpoint) const
{
    // this method requires a shared_lock or lock on at least the fragment
    // that would hold the outpoint. locking all fragments is also acceptable
    return cacheCoins.find(outpoint);
}

CCoinsMap::iterator CCoinsViewCache::_GetCoinFromCacheOrDisk(const COutPoint &outpoint) const
{
    // this method requires a lock on at least the fragment
    // that would hold the outpoint. locking all fragments is also acceptable
    CCoinsMap::iterator it;
    // check the cache, its quick and would save a lot of time if it were in there
    it = _GetCoinFromCache(outpoint);
    if (it != cacheCoins.end())
    {
        return it;
    }
    // coin was not in the cache, get it from disk
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
    {
        return cacheCoins.end();
    }
    it = cacheCoins.emplace(outpoint, tmp).first;
    if (it->second.coin.IsSpent())
    {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        it->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
    if (nBestCoinHeight < it->second.coin.nHeight)
    {
        nBestCoinHeight = it->second.coin.nHeight;
    }
    return it;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const
{
    CCoinsMap::iterator it;
    cacheCoins.lock_shared_ForOutpoint(outpoint, __FILE__, __LINE__);
    it = _GetCoinFromCache(outpoint);
    if (it != cacheCoins.end())
    {
        coin = it->second.coin;
        cacheCoins.unlock_shared_ForOutpoint(outpoint);
        return true;
    }
    cacheCoins.unlock_shared_ForOutpoint(outpoint);
    // need lock for _GetCoinFromCacheOrDisk because it will write the coin
    // to the cache
    cacheCoins.lock_ForOutpoint(outpoint, __FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        it = _GetCoinFromCacheOrDisk(outpoint);
    }
    if (it != cacheCoins.end())
    {
        coin = it->second.coin;
        cacheCoins.unlock_ForOutpoint(outpoint);
        return true;
    }
    cacheCoins.unlock_ForOutpoint(outpoint);
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin &&coin, bool possible_overwrite)
{
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable())
    {
        return;
    }
    CCoinsMap::iterator it;
    bool inserted;

    cacheCoins.lock_ForOutpoint(outpoint, __FILE__, __LINE__);
    std::tie(it, inserted) = cacheCoins.emplace(outpoint);
    bool fresh = false;
    if (!inserted)
    {
        WRITELOCK(cs_utxo);
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite)
    {
        if (!it->second.coin.IsSpent())
        {
            cacheCoins.unlock_ForOutpoint(outpoint);
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    {
        WRITELOCK(cs_utxo);
        cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
        if (nBestCoinHeight < it->second.coin.nHeight)
        {
            nBestCoinHeight = it->second.coin.nHeight;
        }
    }
    cacheCoins.unlock_ForOutpoint(outpoint);
}

void CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin *moveout)
{
    CCoinsMap::iterator it;
    cacheCoins.lock_ForOutpoint(outpoint, __FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        it = _GetCoinFromCacheOrDisk(outpoint);
    }
    if (it == cacheCoins.end())
    {
        cacheCoins.unlock_ForOutpoint(outpoint);
        printf("COIN NOT SPEND COIN WITH HASH %s, IT DOES NOT EXIST \n", outpoint.hash.ToString().c_str());
        return;
    }
    {
        WRITELOCK(cs_utxo);
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (moveout)
    {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH)
    {
        uint8_t i = 0;
        cacheCoins.erase(i, it);
    }
    else
    {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.coin.Clear();
    }
    cacheCoins.unlock_ForOutpoint(outpoint);
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const
{
    CCoinsMap::iterator it;
    cacheCoins.lock_shared_ForOutpoint(outpoint, __FILE__, __LINE__);
    it = _GetCoinFromCache(outpoint);
    if (it != cacheCoins.end())
    {
        if (!it->second.coin.IsSpent())
        {
            cacheCoins.unlock_shared_ForOutpoint(outpoint);
            return true;
        }
        cacheCoins.unlock_shared_ForOutpoint(outpoint);
        return false;
    }
    cacheCoins.unlock_shared_ForOutpoint(outpoint);
    cacheCoins.lock_ForOutpoint(outpoint, __FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        it = _GetCoinFromCacheOrDisk(outpoint);
    }
    if (it != cacheCoins.end())
    {
        if (!it->second.coin.IsSpent())
        {
            cacheCoins.unlock_ForOutpoint(outpoint);
            return true;
        }
    }
    cacheCoins.unlock_ForOutpoint(outpoint);
    return false;
}

bool CCoinsViewCache::GetCoinFromDB(const COutPoint &outpoint) const
{
    Coin coin;
    if (!base->GetCoin(outpoint, coin))
        return false;

    cacheCoins.lock_ForOutpoint(outpoint, __FILE__, __LINE__);
    CCoinsMap::iterator ret = cacheCoins.emplace(outpoint, coin).first;
    if (ret->second.coin.IsSpent())
    {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    {
        WRITELOCK(cs_utxo);
        cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
        if (nBestCoinHeight < ret->second.coin.nHeight)
        {
            nBestCoinHeight = ret->second.coin.nHeight;
        }
    }
    bool res = !ret->second.coin.IsSpent();
    cacheCoins.unlock_ForOutpoint(outpoint);
    return res;
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint, bool &fSpent) const
{
    cacheCoins.lock_shared_ForOutpoint(outpoint, __FILE__, __LINE__);
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
    {
        fSpent = it->second.coin.IsSpent();
        cacheCoins.unlock_shared_ForOutpoint(outpoint);
        return true;
    }
    cacheCoins.unlock_shared_ForOutpoint(outpoint);
    return false;
}

uint256 CCoinsViewCache::GetBestBlock() const
{
    uint256 newBestBlock;
    {
        READLOCK(cs_utxo);
        if (hashBlock.IsNull() == false)
        {
            return hashBlock;
        }
        newBestBlock = base->GetBestBlock();
    }
    WRITELOCK(cs_utxo);
    hashBlock = newBestBlock;
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn)
{
    WRITELOCK(cs_utxo);
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins,
    const uint256 &hashBlockIn,
    const uint64_t nBestCoinHeightIn,
    size_t &nChildCachedCoinsUsage)
{
    // we should have an exclusie lock on all maps before calling this method
    // this method is only called from inside Flush()
    CCoinsMap::iterator it = mapCoins.begin();
    uint8_t i = 0;
    while(it != mapCoins.end())
    {
        if (it->second.flags & CCoinsCacheEntry::DIRTY)
        { // Ignore non-dirty entries (optimization).
            // Update usage of the child cache before we do any swapping and deleting
            nChildCachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();

            CCoinsMap::iterator itUs = cacheCoins.find(it->first);
            if (itUs == cacheCoins.end())
            {
                // The parent cache does not have an entry, while the child does
                // We can ignore it if it's both FRESH and pruned in the child
                if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent()))
                {
                    // Otherwise we will need to create it in the parent
                    // and move the data up and mark it as dirty
                    CCoinsCacheEntry &entry = cacheCoins[it->first];
                    entry.coin = std::move(it->second.coin);
                    cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                    entry.flags = CCoinsCacheEntry::DIRTY;
                    // We can mark it FRESH in the parent if it was FRESH in the child
                    // Otherwise it might have just been flushed from the parent's cache
                    // and already exist in the grandparent
                    if (it->second.flags & CCoinsCacheEntry::FRESH)
                    {
                        entry.flags |= CCoinsCacheEntry::FRESH;
                    }
                }
            }
            else
            {
                // Assert that the child cache entry was not marked FRESH if the
                // parent cache entry has unspent outputs. If this ever happens,
                // it means the FRESH flag was misapplied and there is a logic
                // error in the calling code.
                if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent())
                    throw std::logic_error(
                        "FRESH flag misapplied to cache entry for base transaction with spendable outputs");

                // Found the entry in the parent cache
                if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent())
                {
                    // The grandparent does not have an entry, and the child is
                    // modified and being pruned. This means we can just delete
                    // it from the parent.
                    cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                    cacheCoins.erase(i, itUs);
                }
                else
                {
                    // A normal modification.
                    cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                    itUs->second.coin = std::move(it->second.coin);
                    cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                    itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                }
            }
            it = mapCoins.erase(i, it);
        }
        else
        {
            mapCoins.next(i, it);
        }
    }
    hashBlock = hashBlockIn;
    if (nBestCoinHeightIn > nBestCoinHeight)
    {
        nBestCoinHeight = nBestCoinHeightIn;
    }
    return true;
}

bool CCoinsViewCache::Flush()
{
    bool fOk;
    cacheCoins.lock(__FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        fOk = base->BatchWrite(cacheCoins, hashBlock, nBestCoinHeight, cachedCoinsUsage);
    }
    cacheCoins.unlock();
    return fOk;
}

void CCoinsViewCache::Trim(size_t nTrimSize) const
{
    cacheCoins.lock(__FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        uint64_t nTrimmed = 0;
        uint64_t nTrimmedByHeight = 0;
        static uint64_t nTrimHeightDelta = nBestCoinHeight * 0.80; // This is where we attempt to do our first trim
        uint64_t nTrimHeight = nBestCoinHeight - nTrimHeightDelta;

        // Begin first Trim loop. This loop will trim coins from cache by the coin height, removing the oldest coins first.
        // This has been proven to improve sync performance significantly for nodes that can not hold the entire dbcache
        // in memory.
        bool fDone = false;
        uint64_t nSmallestDelta = 50; // number of blocks to adjust trim height by
        while (!fDone && _DynamicMemoryUsage() > nTrimSize)
        {
            LOG(COINDB, "cacheCoinsUsage at start: %d total dynamic usage: %d trim to size: %d nBestCoinHeight: %d "
                        "trim height:%d\n",
                cachedCoinsUsage, _DynamicMemoryUsage(), nTrimSize, nBestCoinHeight, nTrimHeight);

            CCoinsMap::iterator iter = cacheCoins.begin();
            uint8_t i = 0;
            while (_DynamicMemoryUsage() > nTrimSize)
            {
                if (iter == cacheCoins.end())
                {
                    fDone = true;
                    break;
                }
                if (iter->second.flags == 0 && iter->second.coin.nHeight < nTrimHeight)
                {
                    cachedCoinsUsage -= iter->second.coin.DynamicMemoryUsage();
                    iter = cacheCoins.erase(i ,iter);
                    nTrimmed++;
                    nTrimmedByHeight++;
                }
                else
                {
                    cacheCoins.next(i, iter);
                }
            }
            if (cacheCoins.size() == 0 || _DynamicMemoryUsage() > nTrimSize)
            {
                fDone = true;
            }
            // Gradually increase the nTrimHeight if we didn't trim enought entries.
            if (fDone && _DynamicMemoryUsage() > nTrimSize && nTrimHeightDelta > nSmallestDelta)
            {
                if (nTrimHeightDelta <= nSmallestDelta * 100)
                    nTrimHeightDelta =
                        (nTrimHeightDelta > (nSmallestDelta * 2) ? nTrimHeightDelta - (nSmallestDelta * 2) : 0);
                else if (nTrimHeightDelta <= nSmallestDelta * 400)
                    nTrimHeightDelta =
                        (nTrimHeightDelta > (nSmallestDelta * 10) ? nTrimHeightDelta - (nSmallestDelta * 10) : 0);
                else
                    nTrimHeightDelta =
                        (nTrimHeightDelta > (nSmallestDelta * 200) ? nTrimHeightDelta - (nSmallestDelta * 200) : 0);

                nTrimHeight = (nBestCoinHeight > nTrimHeightDelta ? nBestCoinHeight - nTrimHeightDelta : 0);
                // We're not done yet. We've adjusted the nTrimHeight so we have to go back and trim again.
                fDone = false;
                LOG(COINDB, "Re-adjusting trim height to %d using a trim height delta of %d\n", nTrimHeight,
                    nTrimHeightDelta);
            }
        }
        // If trimming by coin height failed to find any or enough coins to trim then trim the cache by ignoring
        // coin height. While this is not ideal we still have to trim to keep the cache from growing unbounded.
        CCoinsMap::iterator iter = cacheCoins.begin();
        uint8_t i = 0;
        while (_DynamicMemoryUsage() > nTrimSize)
        {
            if (iter == cacheCoins.end())
            {
                break;
            }
            // Only erase entries that have not been modified
            if (iter->second.flags == 0)
            {
                cachedCoinsUsage -= iter->second.coin.DynamicMemoryUsage();
                iter = cacheCoins.erase(i, iter);
                nTrimmed++;
            }
            else
            {
                cacheCoins.next(i, iter);
            }
        }
        if (nTrimmed > 0)
        {
            LOG(COINDB, "Trimmed %d by coin height\n", nTrimmedByHeight);
            LOG(COINDB, "Trimmed %ld from the CoinsViewCache, current size after trim: %ld and usage %ld bytes\n", nTrimmed,
                cacheCoins.size(), cachedCoinsUsage);
        }
        // If we're not trimming anything then gradually walk the trim height backwards from the tip.  This is to adjust
        // and account for the possiblity that the average block size could be getting smaller for certain periods of time
        // and thus we can keep more of the recent coins from getting trimmed.
        if (nTrimmedByHeight == 0 && nTrimmed == 0)
        {
            nTrimHeightDelta += nSmallestDelta;
            if (nTrimHeightDelta > nBestCoinHeight)
                nTrimHeightDelta = nBestCoinHeight;
            nTrimHeight = nBestCoinHeight - nTrimHeightDelta;
            LOG(COINDB, "Re-adjusting trim height to %d using a trim height delta of %d\n", nTrimHeight, nTrimHeightDelta);
        }
    }
    cacheCoins.unlock();
}

void CCoinsViewCache::Uncache(const COutPoint &hash)
{
    cacheCoins.lock_ForOutpoint(hash, __FILE__, __LINE__);
    CCoinsMap::iterator it = cacheCoins.find(hash);
    // only uncache coins that are not dirty.
    if (it != cacheCoins.end())
    {
        if (it->second.flags == 0)
        {
            {
                WRITELOCK(cs_utxo);
                cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
            }
            uint8_t i = 0;
            cacheCoins.erase(i, it);
        }
    }
    cacheCoins.unlock_ForOutpoint(hash);
}

void CCoinsViewCache::UncacheTx(const CTransaction &tx)
{
    for (const CTxIn &txin : tx.vin)
    {
        Uncache(txin.prevout);
    }
}

size_t CCoinsViewCache::GetCacheSize() const
{
    cacheCoins.lock_shared(__FILE__, __LINE__);
    size_t size = cacheCoins.size();
    cacheCoins.unlock_shared();
    return size;
}

CAmount CCoinsViewCache::GetValueIn(const CTransaction &tx) const
{
    if (tx.IsCoinBase())
    {
        return 0;
    }
    CAmount nResult = 0;
    cacheCoins.lock_shared(__FILE__, __LINE__);
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        Coin coin;
        if (GetCoin(tx.vin[i].prevout, coin))
        {
            nResult += coin.out.nValue;
        }
    }
    cacheCoins.unlock_shared();
    return nResult;
}

bool CCoinsViewCache::HaveInputs(const CTransaction &tx) const
{
    if (!tx.IsCoinBase())
    {
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            if (!HaveCoin(tx.vin[i].prevout))
            {
                return false;
            }
        }
    }
    return true;
}

double CCoinsViewCache::GetPriority(const CTransaction &tx, int nHeight, CAmount &inChainInputValue) const
{
    inChainInputValue = 0;
    if (tx.IsCoinBase())
    {
        return 0.0;
    }
    double dResult = 0.0;
    CCoinsMap::iterator it;
    std::vector<CTxIn> vMissing;
    Coin coin;
    cacheCoins.lock_shared(__FILE__, __LINE__);
    for (const CTxIn &txin : tx.vin)
    {
        it =_GetCoinFromCache(txin.prevout);
        if (it == cacheCoins.end())
        {
            vMissing.emplace_back(txin);
            continue;
        }
        coin = it->second.coin;
        if (coin.IsSpent())
        {
            continue;
        }
        if (coin.nHeight <= nHeight)
        {
            dResult += coin.out.nValue * (nHeight - coin.nHeight);
            inChainInputValue += coin.out.nValue;
        }
    }
    cacheCoins.unlock_shared();
    cacheCoins.lock(__FILE__, __LINE__);
    {
        WRITELOCK(cs_utxo);
        for (const CTxIn &txin : vMissing)
        {
            it = _GetCoinFromCacheOrDisk(txin.prevout);
            coin = it->second.coin;
            if (coin.IsSpent())
            {
                continue;
            }
            if (coin.nHeight <= nHeight)
            {
                dResult += coin.out.nValue * (nHeight - coin.nHeight);
                inChainInputValue += coin.out.nValue;
            }
        }
    }
    cacheCoins.unlock();
    return tx.ComputePriority(dResult);
}


CCoinsViewCursor::~CCoinsViewCursor() {}
static const size_t nMaxOutputsPerBlock =
    DEFAULT_LARGEST_TRANSACTION / ::GetSerializeSize(CTxOut(), SER_NETWORK, PROTOCOL_VERSION);

CoinAccessor::CoinAccessor(const CCoinsViewCache &view, const uint256 &txid)
    : cache(&view)
{
    found = false;
    output.SetNull();
    COutPoint iter(txid, 0);
    coin = &emptyCoin;
    Coin tmp;
    bool loaded = false;
    cache->cacheCoins.lock(__FILE__, __LINE__);
    {
        WRITELOCK(cache->cs_utxo);
        while (iter.n < nMaxOutputsPerBlock)
        {
            it = cache->_GetCoinFromCacheOrDisk(iter);
            if (it != cache->cacheCoins.end())
            {
                tmp = it->second.coin;
                if (!tmp.IsSpent())
                {
                    loaded = true;
                    break;
                }
            }
            ++iter.n;
        }
    }
    cache->cacheCoins.unlock();
    if (loaded)
    {
        cache->cacheCoins.lock_shared_ForOutpoint(iter, __FILE__, __LINE__);
        it = cache->_GetCoinFromCache(iter);
        if (it != cache->cacheCoins.end())
        {
            found = true;
            output = iter;
            coin = &it->second.coin;
            return;
        }
        // else it is still emptyCoin as it was initially
        cache->cacheCoins.unlock_shared_ForOutpoint(iter);
    }
    // we did not find anything, coin is still set to emptyCoin
}

CoinAccessor::CoinAccessor(const CCoinsViewCache &cacheObj, const COutPoint &_output)
    : cache(&cacheObj), output(_output)
{
    found = false;
    cache->cacheCoins.lock_ForOutpoint(_output, __FILE__, __LINE__);
    {
        WRITELOCK(cache->cs_utxo);
        it = cache->_GetCoinFromCacheOrDisk(_output);
    }
    if (it == cache->cacheCoins.end())
    {
        // no coin so return
        cache->cacheCoins.unlock_ForOutpoint(_output);
        return;
    }
    cache->cacheCoins.unlock_ForOutpoint(_output);
    cache->cacheCoins.lock_shared_ForOutpoint(_output, __FILE__, __LINE__);
    it = cache->_GetCoinFromCache(_output);
    if (it != cache->cacheCoins.end())
    {
        found = true;
        coin = &it->second.coin;
        return;
    }
    cache->cacheCoins.unlock_shared_ForOutpoint(_output);
}

CoinAccessor::~CoinAccessor()
{
    coin = nullptr;
    if (found == true)
    {
        cache->cacheCoins.unlock_shared_ForOutpoint(output);
    }
}

// it is probably possible to modify CoinModifier to only lock for the map it needs
// but it is only used by bitcoin-tx when signing so this is not very important to do
CoinModifier::CoinModifier(const CCoinsViewCache &cacheObj, const COutPoint &output) : cache(&cacheObj)
{
    cache->cacheCoins.lock(__FILE__, __LINE__);
    {
        WRITELOCK(cache->cs_utxo);
        it = cache->_GetCoinFromCacheOrDisk(output);
    }
    if (it != cache->cacheCoins.end())
    {
        coin = &it->second.coin;
    }
    else
    {
        coin = &emptyCoin;
    }
}

CoinModifier::~CoinModifier()
{
    coin = nullptr;
    cache->cacheCoins.unlock();
}

void AddCoins(CCoinsViewCache &cache, const CTransaction &tx, int nHeight)
{
    bool fCoinbase = tx.IsCoinBase();
    const uint256 &txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        // Pass fCoinbase as the possible_overwrite flag to AddCoin, in order to correctly
        // deal with the pre-BIP30 occurrances of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), fCoinbase);
    }
}

void SpendCoins(const CTransaction &tx, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase())
    {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin)
        {
            txundo.vprevout.emplace_back();
            inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
        }
    }
}

void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight)
{
    // mark inputs spent
    SpendCoins(tx, inputs, txundo, nHeight);
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction &tx, CCoinsViewCache &inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}
