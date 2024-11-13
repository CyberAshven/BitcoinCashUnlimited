// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "promotable_shared_mutex.h"
#include "test_threadsupport.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(psm_promotion_tests, TestSetup)

#ifdef DEBUG_LOCKORDER

struct psm_watcher : public promotable_shared_mutex
{
    bool get_write_entered() { return _write_entered.load(); }
    bool get_promotion_entered() { return _promote.load(); }
};

psm_watcher psm;
std::vector<int> psm_guarded_vector;
static std::atomic<int> shared_locks {0};

void shared_only()
{
    psm.lock_shared();
    shared_locks.store(shared_locks.load() + 1);
    // wait until promotion is requested to unlock
    while (psm.get_promotion_entered() != true) ;
    psm.unlock_shared();
}

void exclusive_only()
{
    psm.lock();
    psm_guarded_vector.push_back(4);
    psm.unlock();
}

void shared_with_late_promotion()
{
    psm.lock_shared();
    shared_locks.store(shared_locks.load() + 1);
    // we want the exclusive lock to attempt to lock before promoting
    // to check that the promotion is done first,
    while (psm.get_write_entered() == false) ;
    bool promoted = psm.try_promotion();
    BOOST_CHECK_EQUAL(promoted, true);
    psm_guarded_vector.push_back(7);
    psm.unlock();
}

void promoting_thread()
{
    psm.lock_shared();
    shared_locks.store(shared_locks.load() + 1);
    bool promoted = psm.try_promotion();
    BOOST_CHECK_EQUAL(promoted, true);
    psm_guarded_vector.push_back(7);
    psm.unlock();
}

/*
 * if a thread askes for a promotion while no other thread
 * is currently asking for a promotion it will be put in line to grab the next
 * exclusive lock even if another threads are waiting using lock()
 *
 * This test covers lock promotion from shared to exclusive.
 *
 */

// Note: It is likely that only one of these tests is needed

// lock shared with 4 threads then lock shared with thread that will promote
// try to promote while another thread locks for exclusive, promotion should always
// get exclusive ownership before the other thread locks exclusive. This test is
// a race condition form of the test below it, it is undetermined if the promotion
// thread will try to promote first or if the exclusive lock will try to lock first
BOOST_AUTO_TEST_CASE(psm_try_promotion_exec_first)
{
    // clear the data vector at test start
    shared_locks = 0;
    psm_guarded_vector.clear();
    // test promotions
    std::thread reader_one(shared_only);
    std::thread reader_two(shared_only);
    std::thread reader_three(shared_only);
    std::thread reader_four(shared_only);
    while (shared_locks.load() != 4) ;
    std::thread promote(promoting_thread);
    while (shared_locks.load() != 5) ;
    std::thread exec(exclusive_only);

    reader_one.join();
    reader_two.join();
    reader_three.join();
    reader_four.join();
    promote.join();
    exec.join();

    // 7 was added by the promoted thread, it should appear first in the vector
    psm.lock_shared();
    BOOST_CHECK_EQUAL(7, psm_guarded_vector[0]);
    BOOST_CHECK_EQUAL(4, psm_guarded_vector[1]);
    psm.unlock_shared();
}

// The same as the test above except the exclusive thread always tries to lock before
// the promotion thread tries to promote
BOOST_AUTO_TEST_CASE(psm_try_promotion_exec_second)
{
    // clear the data vector at test start
    shared_locks = 0;
    psm_guarded_vector.clear();
    // test promotions
    std::thread reader_one(shared_only);
    std::thread reader_two(shared_only);
    std::thread reader_three(shared_only);
    std::thread reader_four(shared_only);
    while (shared_locks.load() != 4) ;
    std::thread promote(shared_with_late_promotion);
    // exclusive needs to wait promoting to take shared
    while (shared_locks.load() != 5) ;
    std::thread exec(exclusive_only);

    reader_one.join();
    reader_two.join();
    reader_three.join();
    reader_four.join();
    promote.join();
    exec.join();

    // 7 was added by the promoted thread, it should appear first in the vector
    psm.lock_shared();
    BOOST_CHECK_EQUAL(7, psm_guarded_vector[0]);
    BOOST_CHECK_EQUAL(4, psm_guarded_vector[1]);
    psm.unlock_shared();
}

#else // ifndef DEBUG_LOCKORDER

BOOST_AUTO_TEST_CASE(psm_promotion_tests)
{
    BOOST_CHECK("Compile with Debug Lockorder to enable the psm promotion tests");
}

#endif // end ifdef DEBUG_LOCKORDER


BOOST_AUTO_TEST_SUITE_END()
