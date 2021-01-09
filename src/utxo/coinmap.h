// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTXO_COINMAP_H
#define BITCOIN_UTXO_COINMAP_H

#include "coin.h"
#include "hashwrapper.h"
#include "sync.h"

class SaltedOutpointHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedOutpointHasher();

    uint64_t operator()(const COutPoint &id) const { return SipHashUint256Extra(k0, k1, id.hash, id.n); }
};

struct CCoinsCacheEntry
{
    Coin coin; // The actual cached data.
    unsigned char flags;

    enum Flags
    {
        DIRTY = (1 << 0), // This cache entry is potentially different from the version in the parent view.
        FRESH = (1 << 1), // The parent view does not have this entry (or it is pruned).
    };

    CCoinsCacheEntry() : flags(0) {}
    explicit CCoinsCacheEntry(Coin &&coin_) : coin(std::move(coin_)), flags(0) {}
    friend bool operator==(CCoinsCacheEntry a, CCoinsCacheEntry b) { return (a.coin == b.coin); }
};

typedef std::unordered_map<COutPoint, CCoinsCacheEntry, SaltedOutpointHasher> _coin_map;

class CCoinMapFragment
{
    friend class CCoinsMap;

public:
    typedef _coin_map::iterator iterator;
    typedef _coin_map::const_iterator const_iterator;

private:
    mutable CSharedCriticalSection _cs_coinMapFragment;
    mutable _coin_map _map;

protected:
    void lock(const char* file, unsigned int line)
    {
        EnterCritical("_cs_coinMapFragment", file, line,
            (void *)(&_cs_coinMapFragment), LockType::RECURSIVE_SHARED_MUTEX, OwnershipType::EXCLUSIVE);
        _cs_coinMapFragment.lock();
    }

    void lock_shared(const char* file, unsigned int line)
    {
        EnterCritical("_cs_coinMapFragment", file, line,
            (void *)(&_cs_coinMapFragment), LockType::RECURSIVE_SHARED_MUTEX, OwnershipType::SHARED);
        _cs_coinMapFragment.lock_shared();
    }

    void unlock()
    {
        _cs_coinMapFragment.unlock();
        LeaveCritical(&_cs_coinMapFragment);
    }

    void unlock_shared()
    {
        _cs_coinMapFragment.unlock_shared();
        LeaveCritical(&_cs_coinMapFragment);
    }

public:
    CCoinMapFragment()
    {
        clear();
    }

    CCoinsCacheEntry &operator[](const COutPoint &outpoint)
    {
        return _map[outpoint];
    }

    void clear()
    {
        _map.clear();
    }

    iterator begin()
    {
        return _map.begin();
    }

    iterator end()
    {
        return _map.end();
    }

    iterator erase(iterator it)
    {
        return _map.erase(it);
    }

    iterator find(const COutPoint &outpoint)
    {
        return _map.find(outpoint);
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint)
    {
        return _map.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint, const CCoinsCacheEntry &entry)
    {
        return _map.emplace(outpoint, std::move(entry));
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint, Coin &coin)
    {
        return _map.emplace(
            std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(coin)));
    }

    size_t size()
    {
        return _map.size();
    }

    size_t DynamicUsage()
    {
        return memusage::DynamicUsage(_map);
    }

    size_t CalculateMemoryUsageUsingCoins()
    {
        size_t nUsage = 0;
        for (iterator it = _map.begin(); it != _map.end(); it++)
        {
            nUsage += it->second.coin.DynamicMemoryUsage();
        }
        return nUsage;
    }

};

class CCoinsMap
{
private:
    uint8_t _num_fragments;

protected:
    uint8_t getMapForNibble(uint8_t &nibble)
    {
         uint8_t res =  nibble % _num_fragments;
         return res;
    }
    std::vector<CCoinMapFragment*> vMaps;

public:
    typedef _coin_map::iterator iterator;
    typedef _coin_map::const_iterator const_iterator;

    CCoinsMap(const uint8_t &__num_fragments = 4)
    {
        _num_fragments = __num_fragments;
        if (_num_fragments > 16)
        {
            _num_fragments = 16;
        }
        if (_num_fragments == 0)
        {
            _num_fragments = 4;
        }
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            vMaps.emplace_back(std::move(new CCoinMapFragment()));
        }
    }

    ~CCoinsMap()
    {
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            vMaps[i]->clear();
            delete vMaps[i];
        }
    }

    // lock from index 0 to n
    void lock(const char* file, unsigned int line)
    {
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            vMaps[i]->lock(file, line);
        }
    }
    void lock_shared(const char* file, unsigned int line)
    {
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            vMaps[i]->lock_shared(file, line);
        }
    }

    // unlock in the reverse order of locking, from index n to 0
    void unlock()
    {
        for (uint8_t i = _num_fragments ; i > 0 ; i--)
        {
            vMaps[i-1]->unlock();
        }
    }
    void unlock_shared()
    {
        for (uint8_t i = _num_fragments; i > 0 ; i--)
        {
            vMaps[i-1]->unlock_shared();
        }
    }

    void clear()
    {
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            // this clear might be redundant because of destructor behaviour
            vMaps[i]->clear();
        }
    }

    CCoinsCacheEntry &operator[](const COutPoint &outpoint)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return (*vMaps[map_num])[outpoint];
    }

    void lock_ForOutpoint(const COutPoint &outpoint, const char* file, unsigned int line)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->lock(file, line);
    }

    void unlock_ForOutpoint(const COutPoint &outpoint)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->unlock();
    }

    void lock_shared_ForOutpoint(const COutPoint &outpoint, const char* file, unsigned int line)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->lock_shared(file, line);
    }

    void unlock_shared_ForOutpoint(const COutPoint &outpoint)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->unlock_shared();
    }

    iterator erase(uint8_t &i, iterator it)
    {
        uint8_t nibble = it->first.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        it = vMaps[map_num]->erase(it);
        if (it == end())
        {
            ++i;
            if (i < _num_fragments)
            {
                it = vMaps[map_num]->begin();
            }
        }
        return it;
    }

    iterator find(const COutPoint &outpoint)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->find(outpoint);
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->emplace(outpoint);
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint, const CCoinsCacheEntry &entry)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->emplace(outpoint, entry);
    }

    inline std::pair<iterator, bool> emplace(const COutPoint &outpoint, Coin &coin)
    {
        uint8_t nibble = outpoint.hash.GetFirstNibble();
        uint8_t map_num = getMapForNibble(nibble);
        return vMaps[map_num]->emplace(outpoint, coin);
    }

    iterator begin()
    {
        return vMaps[0]->begin();
    }

    // end of all maps is the same so simply use the end of the first
    iterator end()
    {
        return vMaps[0]->end();
    }

    bool next(uint8_t &i, iterator &iter)
    {
        ++iter;
        if (iter == vMaps[i]->end())
        {
            ++i;
            if (i >= _num_fragments)
            {
                return false;
            }
            else
            {
                iter = vMaps[i]->begin();
            }
        }
        return true;
    }

    size_t size()
    {
        size_t nSize = 0;
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            nSize += vMaps[i]->size();
        }
        return nSize;
    }

    size_t DynamicUsage()
    {
        size_t nUsage = 0;
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            nUsage += vMaps[i]->DynamicUsage();
        }
        return nUsage;
    }

    size_t CalculateMemoryUsageUsingCoins()
    {
        size_t nUsage = 0;
        for (uint8_t i = 0; i < _num_fragments; i++)
        {
            nUsage += vMaps[i]->CalculateMemoryUsageUsingCoins();
        }
        return nUsage;
    }
};

#endif // BITCOIN_UTXO_COINMAP_H
