// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "promotable_shared_mutex.h"
#include "test_threadsupport.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(psm_simple_tests, TestSetup)

promotable_shared_mutex psm;

// basic lock and unlock tests
BOOST_AUTO_TEST_CASE(psm_lock_unlock)
{
    // exclusive lock once
    psm.lock();

// try to unlock_shared an exclusive lock
// we should error here because exclusive locks can
// be not be unlocked by shared_ unlock method
#ifdef DEBUG_ASSERTION
    BOOST_CHECK_THROW(psm.unlock_shared(), std::logic_error);
#endif

    // unlock exclusive lock

    BOOST_CHECK_NO_THROW(psm.unlock());

    // exclusive lock once
    psm.lock();

    // try to unlock exclusive lock
    BOOST_CHECK_NO_THROW(psm.unlock());

#ifdef DEBUG_ASSERTION
    // try to unlock exclusive lock more times than we locked
    BOOST_CHECK_THROW(psm.unlock(), std::logic_error);
#endif

    // test complete
}

// basic lock_shared and unlock_shared tests
BOOST_AUTO_TEST_CASE(psm_lock_shared_unlock_shared)
{
    // lock shared
    psm.lock_shared();

#ifdef DEBUG_ASSERTION
    // try to unlock exclusive when we only have shared
    BOOST_CHECK_THROW(psm.unlock(), std::logic_error);
#endif

    // unlock shared
    psm.unlock_shared();

#ifdef DEBUG_ASSERTION
    // we should error here because we are unlocking more times than we locked
    BOOST_CHECK_THROW(psm.unlock_shared(), std::logic_error);
#endif

    // test complete
}

// basic try_lock tests
BOOST_AUTO_TEST_CASE(psm_try_lock)
{
    // try lock
    psm.try_lock();

#ifdef DEBUG_ASSERTION
    // try to unlock_shared an exclusive lock
    // we should error here because exclusive locks can
    // be not be unlocked by shared_ unlock method
    BOOST_CHECK_THROW(psm.unlock_shared(), std::logic_error);
#endif

    // unlock exclusive lock
    BOOST_CHECK_NO_THROW(psm.unlock());

    // try lock
    psm.try_lock();

    // try to unlock exclusive lock
    BOOST_CHECK_NO_THROW(psm.unlock());

#ifdef DEBUG_ASSERTION
    // try to unlock exclusive lock more times than we locked
    BOOST_CHECK_THROW(psm.unlock(), std::logic_error);
#endif

    // test complete
}

// basic try_lock_shared tests
BOOST_AUTO_TEST_CASE(psm_try_lock_shared)
{
    // try lock shared
    psm.try_lock_shared();

#ifdef DEBUG_ASSERTION
    // unlock exclusive while we have shared lock
    BOOST_CHECK_THROW(psm.unlock(), std::logic_error);
#endif

    // unlock shared
    BOOST_CHECK_NO_THROW(psm.unlock_shared());

#ifdef DEBUG_ASSERTION
    // we should error here because we are unlocking more times than we locked
    BOOST_CHECK_THROW(psm.unlock_shared(), std::logic_error);
#endif

    // test complete
}


BOOST_AUTO_TEST_SUITE_END()
