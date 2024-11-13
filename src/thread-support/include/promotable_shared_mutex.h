// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THREADSUPPORT_INCLUDE_PROMOTABLESHAREDMUTEX_H
#define THREADSUPPORT_INCLUDE_PROMOTABLESHAREDMUTEX_H

#include <condition_variable>
#include <mutex> // mutex, unique_lock
#include <thread>

#ifdef DEBUG_LOCKORDER
#include <atomic>
#endif

class promotable_shared_mutex
{
protected:
    std::mutex _mutex;
    std::condition_variable _write_gate;
    std::condition_variable _read_gate;
    std::condition_variable _promotion_gate;

// atmoic variables are needed for test suite
#ifdef DEBUG_LOCKORDER
    std::atomic<bool> _write_entered;
    std::atomic<bool> _promote;
    std::atomic<uint64_t> _n_readers;
#else
    bool _write_entered;
    bool _promote;
    uint64_t _n_readers;
#endif

public:
    promotable_shared_mutex()
    {
        _write_entered = 0;
        _n_readers = 0;
        _promote = 0;
    }

    // Exclusive ownership
    void lock();
    bool try_lock();
    void unlock();

    // Shared ownership
    void lock_shared();
    bool try_lock_shared();
    void unlock_shared();

    // Promotion
    /**
     * Become "next in line" for exclusive ownership of the mutex if the promotion
     * slot is not already occupied by another thread.
     *
     * When called by a thread that has shared ownership or no ownership, attempt to
     * obtain the promotion slot. Only one thread can hold the promotion slot at a time.
     * While promotion slot is obtained and waiting for exclusive ownership this
     * call is blocking.
     *
     * Precondition: The calling thread must hold a shared lock on the mutex.
     *
     * @param none
     * @return: false on failure to be put in the promotion slot because
     * it is already occupied by another thread.
     * true when exclusive ownership has been obtained
     */
    bool try_promotion();
};

#endif // THREADSUPPORT_MUTEXES_PROMOTABLESHAREDMUTEX_H
