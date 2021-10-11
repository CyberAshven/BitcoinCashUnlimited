// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "promotable_shared_mutex.h"

// Exclusive ownership
void promotable_shared_mutex::lock()
{
    std::unique_lock<std::mutex> lock(_mutex);
    while (_write_entered || _promote)
    {
        _write_gate.wait(lock);
    }
    _write_entered = 1;
    // while _n_readers is not 0
    while (_n_readers || _promote)
    {
        _read_gate.wait(lock);
    }
}

bool promotable_shared_mutex::try_lock()
{
    std::unique_lock<std::mutex> lock(_mutex, std::try_to_lock);
    if (lock.owns_lock() && !_n_readers && !_write_entered && !_promote)
    {
        _write_entered = 1;
        return true;
    }
    return false;
}

void promotable_shared_mutex::unlock()
{
    std::unique_lock<std::mutex> lock(_mutex);
#ifdef DEBUG_ASSERTION
    if (_write_entered == 0 && _promote == 0)
    {
        throw std::logic_error("unlock called when no thread has exclusive ownership");
    }
#endif
    if (_promote)
    {
        _promote = 0;
        if (_write_entered)
        {
            _read_gate.notify_all();
        }
        else
        {
            _write_gate.notify_all();
        }
    }
    else
    {
        _write_entered = 0;
        _write_gate.notify_all();
    }
}

// Shared ownership
void promotable_shared_mutex::lock_shared()
{
    std::unique_lock<std::mutex> lock(_mutex);
    while (_write_entered || _promote)
    {
        _write_gate.wait(lock);
    }
    ++_n_readers;
}

bool promotable_shared_mutex::try_lock_shared()
{
    std::unique_lock<std::mutex> lock(_mutex, std::try_to_lock);
    if (lock.owns_lock() && !_write_entered && !_promote)
    {
        ++_n_readers;
        return true;
    }
    return false;
}

void promotable_shared_mutex::unlock_shared()
{
    std::unique_lock<std::mutex> lock(_mutex);
#ifdef DEBUG_ASSERTION
    if (_n_readers == 0)
    {
        throw std::logic_error("unlock_shared called when no thread has shared ownership");
    }
#endif
    --_n_readers;
    if (_n_readers == 0)
    {
        if (_promote)
        {
            _promotion_gate.notify_one();
        }
        else if (_write_entered)
        {
            _read_gate.notify_one();
        }
        else
        {
            _write_gate.notify_one();
        }
    }
    else
    {
        _write_gate.notify_one();
    }
}

// Promotion
bool promotable_shared_mutex::try_promotion()
{
    std::unique_lock<std::mutex> lock(_mutex);
#ifdef DEBUG_ASSERTION
    if (_n_readers == 0)
    {
        throw std::logic_error("unlock_shared called when no thread has shared ownership");
    }
#endif
    if (_promote != 0)
    {
        return false;
    }
    _promote = 1;
    --_n_readers;
    // we do not set _write_entered here
    // promotion indicates _write_entered instead
    while (_n_readers)
    {
        _promotion_gate.wait(lock);
    }
    return true;
}
