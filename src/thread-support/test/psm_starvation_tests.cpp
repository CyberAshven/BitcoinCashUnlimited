// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "promotable_shared_mutex.h"
#include "test_threadsupport.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(psm_starvation_tests, TestSetup)

class psm_watcher : public promotable_shared_mutex
{
public:
    size_t get_shared_owners_count() { return _n_readers; }
};

psm_watcher psm;
std::vector<int> psm_guarded_vector;
static std::atomic<int> shared_locks {0};
static std::atomic<bool> proceed_with_promotion {false};

void shared_only()
{
    psm.lock_shared();
    shared_locks.store(shared_locks.load() + 1);
    while (proceed_with_promotion.load() == false) ;
    psm.unlock_shared();
}

void exclusive_only()
{
    psm.lock();
    psm_guarded_vector.push_back(4);
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
 * This test covers blocking of additional shared ownership aquisitions while
 * a thread is waiting for promotion.
 *
 */

BOOST_AUTO_TEST_CASE(psm_test_starvation)
{
    // clear the data vector at test start
    psm_guarded_vector.clear();

    // start up intial shared thread to block immidiate exclusive grabbing
    std::thread one(shared_only);
    while(shared_locks.load() != 1) ;
    std::thread two(shared_only);
    while(shared_locks.load() != 2) ;
    std::thread three(promoting_thread);
    // wait for the first three threads to lock
    while(shared_locks.load() != 3) ;
    std::thread four(exclusive_only);
    // we should always get 3 because five, six, and seven should be blocked by
    // the promotion request leaving only one and two with shared ownership.
    // three lost its shared ownership when it promoted
    BOOST_CHECK_EQUAL(psm.get_shared_owners_count(), 2);
    std::thread five(shared_only);
    BOOST_CHECK_EQUAL(psm.get_shared_owners_count(), 2);
    std::thread six(shared_only);
    BOOST_CHECK_EQUAL(psm.get_shared_owners_count(), 2);
    std::thread seven(shared_only);
    BOOST_CHECK_EQUAL(psm.get_shared_owners_count(), 2);
    // After testing that we could not lock shared while a promotion is waiting,
    // proceed with promotion
    proceed_with_promotion.store(true);

    one.join();
    two.join();
    three.join();
    four.join();
    five.join();
    six.join();
    seven.join();

    // 7 was added by the promoted thread, it should appear first in the vector
    psm.lock_shared();
    BOOST_CHECK_EQUAL(7, psm_guarded_vector[0]);
    BOOST_CHECK_EQUAL(4, psm_guarded_vector[1]);
    psm.unlock_shared();
}

BOOST_AUTO_TEST_SUITE_END()
