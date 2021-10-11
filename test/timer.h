// Copyright (c) 2021 Greg Griffith
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef THREADSUPPORT_TEST_TIMER_H
#define THREADSUPPORT_TEST_TIMER_H

#include <stdint.h>
#include <string>

int64_t GetTimeMillis();
void MilliSleep(int64_t n);

#endif // TIMER_H
