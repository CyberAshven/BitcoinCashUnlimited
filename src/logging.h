// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Server/client environment: argument handling, config file parsing,
 * logging, thread wrappers, startup time
 */
#ifndef BITCOIN_LOGGING_H
#define BITCOIN_LOGGING_H

#include "fs.h"
#include "tinyformat.h"
#include "utiltime.h"

#include <map>
#include <mutex>
#include <stdint.h>
#include <string>

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()

static const bool DEFAULT_LOGTIMEMICROS = false;
static const bool DEFAULT_LOGIPS = true;
static const bool DEFAULT_LOGTIMESTAMPS = true;

inline std::atomic<bool> fLogTimestamps{DEFAULT_LOGTIMESTAMPS};
inline std::atomic<bool> fLogTimeMicros{DEFAULT_LOGTIMEMICROS};
inline std::atomic<bool> fPrintToConsole{false};
inline std::atomic<bool> fPrintToDebugLog{false};
inline std::atomic<bool> fReopenDebugLog{false};

inline std::atomic<std::mutex *> mutexDebugLog{nullptr};
inline std::atomic<FILE *> logger_fileout{nullptr};

/** All logs are automatically CR terminated.  If you want to construct a single-line log out of multiple calls, don't.
    Make your own temporary.  You can make a multi-line log by adding \n in your temporary.
 */
static std::string LogTimestampStr(const std::string &str, std::string &logbuf)
{
    if (!logbuf.size())
    {
        int64_t nTimeMicros = GetLogTimeMicros();
        if (fLogTimestamps)
        {
            logbuf = FormatISO8601DateTime(nTimeMicros / 1000000);
            if (fLogTimeMicros)
                logbuf += strprintf(".%06d", nTimeMicros % 1000000);
        }
        logbuf += ' ' + str;
    }
    else
    {
        logbuf += str;
    }

    if (logbuf.size() && logbuf[logbuf.size() - 1] != '\n')
    {
        logbuf += '\n';
    }

    std::string result = logbuf;
    logbuf.clear();
    return result;
}


static void MonitorLogfile()
{
    // Check if debug.log has been deleted or moved.
    // If so re-open
    static int existcounter = 1;
    static fs::path fileName = GetDataDir() / "debug.log";
    existcounter++;
    if (existcounter % 63 == 0) // Check every 64 log msgs
    {
        bool exists = fs::exists(fileName);
        if (!exists)
        {
            fReopenDebugLog = true;
        }
    }
}

static int FileWriteStr(const std::string &str, FILE *fp) { return fwrite(str.data(), 1, str.size(), fp); }

/** Send a string to the log output */
static int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    std::string logbuf;
    std::string strTimestamped = LogTimestampStr(str, logbuf);

    if (!strTimestamped.size())
    {
        return 0;
    }
    if (fPrintToConsole.load())
    {
        // print to console
        ret = fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    if (fPrintToDebugLog.load())
    {
        std::scoped_lock scoped_lock(*mutexDebugLog.load());

        // buffer if we haven't opened the log yet
        if (logger_fileout == nullptr)
        {
            printf("Logger fileout is null. Did you specify an output file for the logger?\n");
            assert(logger_fileout != nullptr);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog)
            {
                fReopenDebugLog = false;
                fs::path pathDebug = GetDataDir() / "debug.log";
                if (fsbridge::freopen(pathDebug, "a", logger_fileout.load()) != nullptr)
                {
                    setbuf(logger_fileout.load(), nullptr); // unbuffered
                }
            }
            ret = FileWriteStr(strTimestamped, logger_fileout.load());
            MonitorLogfile();
        }
    }
    return ret;
}

// Logging API:
// Use the two macros
// LOG(ctgr,...)
// LOGA(...)
// located further down.
// (Do not use the Logging functions directly)
// Log Categories:
// 64 Bits: (Define unique bits, not 'normal' numbers)
enum
{
    // Turn off clang formatting so we can keep the assignment alinged for readability
    // clang-format off
    NONE           = 0x0, // No logging
    ALL            = 0xFFFFFFFFFFFFFFFFUL, // Log everything

    // LOG Categories:
    THIN           = 0x1,
    MEMPOOL        = 0x2,
    COINDB         = 0x4,
    TOR            = 0x8,

    NET            = 0x10,
    ADDRMAN        = 0x20,
    LIBEVENT       = 0x40,
    HTTP           = 0x80,

    RPC            = 0x100,
    PARTITIONCHECK = 0x200,
    BENCH          = 0x400,
    PRUNE          = 0x800,

    REINDEX        = 0x1000,
    MEMPOOLREJ     = 0x2000,
    BLK            = 0x4000,
    EVICT          = 0x8000,

    PARALLEL       = 0x10000,
    RAND           = 0x20000,
    REQ            = 0x40000,
    BLOOM          = 0x80000,

    ESTIMATEFEE    = 0x100000,
    LCK            = 0x200000,
    PROXY          = 0x400000,
    DBASE          = 0x800000,

    SELECTCOINS    = 0x1000000,
    ZMQ            = 0x2000000,
    QT             = 0x4000000,
    IBD            = 0x8000000,

    GRAPHENE       = 0x10000000,
    RESPEND        = 0x20000000,
    WB             = 0x40000000, // weak blocks
    CMPCT          = 0x80000000, // compact blocks

    ELECTRUM       = 0x100000000,
    MPOOLSYNC      = 0x200000000,
    PRIORITYQ      = 0x400000000,
    DSPROOF        = 0x800000000,

    TWEAKS         = 0x1000000000,
    SCRIPT         = 0x2000000000,
    CAPD           = 0x4000000000,
    VALIDATION     = 0x4000000000000000UL,
    TOKEN          = 0x8000000000000000UL
    // clang-format on
};

namespace Logging
{
/*
To add a new log category:
1) Create a unique 1 bit category mask. (Easiest is to 2* the last enum entry.)
   Put it at the end of enum above.
2) Add an category/string pair to LOGLABELMAP macro below.
*/

// Add corresponding lower case string for the category:
#define LOGLABELMAP                                                                                             \
    {                                                                                                           \
        {NONE, "none"}, {ALL, "all"}, {THIN, "thin"}, {MEMPOOL, "mempool"}, {COINDB, "coindb"}, {TOR, "tor"},   \
            {NET, "net"}, {ADDRMAN, "addrman"}, {LIBEVENT, "libevent"}, {HTTP, "http"}, {RPC, "rpc"},           \
            {PARTITIONCHECK, "partitioncheck"}, {BENCH, "bench"}, {PRUNE, "prune"}, {REINDEX, "reindex"},       \
            {MEMPOOLREJ, "mempoolrej"}, {BLK, "blk"}, {EVICT, "evict"}, {PARALLEL, "parallel"}, {RAND, "rand"}, \
            {REQ, "req"}, {BLOOM, "bloom"}, {LCK, "lck"}, {PROXY, "proxy"}, {DBASE, "dbase"},                   \
            {SELECTCOINS, "selectcoins"}, {ESTIMATEFEE, "estimatefee"}, {QT, "qt"}, {IBD, "ibd"},               \
            {GRAPHENE, "graphene"}, {RESPEND, "respend"}, {WB, "weakblocks"}, {CMPCT, "cmpctblock"},            \
            {ELECTRUM, "electrum"}, {MPOOLSYNC, "mempoolsync"}, {PRIORITYQ, "priorityq"}, {DSPROOF, "dsproof"}, \
            {TWEAKS, "tweaks"}, {SCRIPT, "script"}, {ZMQ, "zmq"}, {VALIDATION, "validation"}, {CAPD, "capd"},   \
            {TOKEN, "token"},                                                                                   \
    }

inline std::map<uint64_t, std::string> logLabelMap = LOGLABELMAP; // Lookup log label from log id.
inline std::atomic<uint64_t> categoriesEnabled = 0; // 64 bit log id mask.

/**
 * Check if a category should be logged
 * @param[in] category
 * returns true if should be logged
 */
inline bool LogAcceptCategory(uint64_t category) { return (categoriesEnabled & category); }
/**
 * Turn on/off logging for a category
 * @param[in] category
 * @param[in] on  True turn on, False turn off.
 */
inline void LogToggleCategory(uint64_t category, bool on)
{
    if (on)
    {
        categoriesEnabled |= category;
    }
    else
    {
        categoriesEnabled &= ~category; // off
    }
}

/**
 * Get a category associated with a string.
 * @param[in] label string
 * returns category
 */
static uint64_t LogFindCategory(const std::string label)
{
    for (const auto &x : logLabelMap)
    {
        if ((std::string)x.second == label)
        {
            return (uint64_t)x.first;
        }
    }
    return NONE;
}

/**
 * Get the label / associated string for a category.
 * @param[in] category
 * returns label
 */
// note: only used in unit tests
inline std::string LogGetLabel(uint64_t category)
{
    std::string label = "none";
    if (logLabelMap.count(category) != 0)
    {
        label = logLabelMap[category];
    }
    return label;
}

/**
 * Get all categories and their state.
 * Formatted for display.
 * returns all categories and states
 */
// Return a string rapresentation of all debug categories and their current status,
// one category per line. If enabled is true it returns only the list of enabled
// debug categories concatenated in a single line.
static std::string LogGetAllString(bool fEnabled = false)
{
    std::string allCategories = "";
    std::string enabledCategories = "";
    for (auto &x : logLabelMap)
    {
        if (x.first == ALL || x.first == NONE)
        {
            continue;
        }
        if (LogAcceptCategory(x.first))
        {
            allCategories += "on ";
            if (fEnabled)
            {
                enabledCategories += (std::string)x.second + " ";
            }
        }
        else
        {
            allCategories += "   ";
        }
        allCategories += (std::string)x.second + "\n";
    }
    // strip last char from enabledCategories if it is eqaul to a blank space
    if (enabledCategories.length() > 0)
    {
        enabledCategories.pop_back();
    }
    return fEnabled ? enabledCategories : allCategories;
}

/**
 * Log a string
 * @param[in] All parameters are "printf like args".
 */
template <typename T1, typename... Args>
inline void LogWrite(const char *fmt, const T1 &v1, const Args &...args)
{
    try
    {
        LogPrintStr(tfm::format(fmt, v1, args...));
    }
    catch (...)
    {
        // Number of format specifiers (%) do not match argument count, etc
    }
}

/**
 * Log a string
 * @param[in] str String to log.
 */
inline void LogWrite(const std::string &str)
{
    LogPrintStr(str); // No formatting for a simple string
}

/**
 * LOGA macro: Always log a string.
 *
 * @param[in] ... "printf like args".
 */
#define LOGA(...) Logging::LogWrite(__VA_ARGS__)

/**
 * Set the logger output file after logger has been initialised
 */
inline void LogSetOutputFile(fs::path pathDebug = GetDataDir() / "debug.log")
{
    // if this assert fails, the LogInit was never called
    assert(mutexDebugLog.load() != nullptr);
    std::scoped_lock scoped_lock(*mutexDebugLog.load());
    // fopen returns a FILE*
    logger_fileout.store(fsbridge::fopen(pathDebug, "a"));
    if (logger_fileout.load())
    {
        setbuf(logger_fileout.load(), nullptr); // unbuffered
    }
    fPrintToDebugLog.store(true);
}

/**
 * Initialize
 */
inline void LogInit(const std::vector<std::string> &categories = {})
{
    // mutexDebugLog should always be nullptr before
    // the logger is initalised
    assert(mutexDebugLog.load() == nullptr);
    // make the mutex and the message vector
    mutexDebugLog.store(new std::mutex);
    std::scoped_lock scoped_lock(*mutexDebugLog.load());
    // when initialising the logger, check if we will use the debug log
    if (fPrintToDebugLog.load())
    {
        assert(logger_fileout == nullptr);
        fs::path pathDebug = GetDataDir() / "debug.log";
        // fopen returns a FILE*
        logger_fileout.store(fsbridge::fopen(pathDebug, "a"));
        if (logger_fileout.load())
        {
            setbuf(logger_fileout.load(), nullptr); // unbuffered
        }
    }

    std::string category = "";
    uint64_t catg = NONE;

    // enable all when given -debug=1 or -debug
    if (categories.size() == 1 && (categories[0] == "" || categories[0] == "1"))
    {
        LogToggleCategory(ALL, true);
    }
    else
    {
        for (std::string const &cat : categories)
        {
            category = boost::algorithm::to_lower_copy(cat);

            // remove the category from the list of enables one
            // if label is suffixed with a dash
            bool toggle_flag = true;

            if (category.length() > 0 && category.at(0) == '-')
            {
                toggle_flag = false;
                category.erase(0, 1);
            }

            if (category == "" || category == "1")
            {
                category = "all";
            }

            catg = LogFindCategory(category);

            if (catg == NONE) // Not a valid category
            {
                continue;
            }

            LogToggleCategory(catg, toggle_flag);
        }
    }
    LOGA("List of enabled categories: %s\n", LogGetAllString(true));
}

/**
 * Write log string to console:
 *
 * @param[in] All parameters are "printf like".
 */
template <typename T1, typename... Args>
inline void LogStdout(const char *fmt, const T1 &v1, const Args &...args)
{
    try
    {
        std::string str = tfm::format(fmt, v1, args...);
        ::fwrite(str.data(), 1, str.size(), stdout);
    }
    catch (...)
    {
        // Number of format specifiers (%) do not match argument count, etc
    }
}

/**
 * Write log string to console:
 * @param[in] str String to log.
 */
inline void LogStdout(const std::string &str)
{
    ::fwrite(str.data(), 1, str.size(), stdout); // No formatting for a simple string
}
} // namespace Logging

// Logging API:
//
/**
 * LOG macro: Log a string if a category is enabled.
 * Note that categories can be ORed, such as: (NET|TOR)
 *
 * @param[in] category -Which category to log
 * @param[in] ... "printf like args".
 */
#define LOG(ctgr, ...)                        \
    do                                        \
    {                                         \
        using namespace Logging;              \
        if (Logging::LogAcceptCategory(ctgr)) \
            Logging::LogWrite(__VA_ARGS__);   \
    } while (0)


// Flush log file (if you know you are about to abort)
inline void LogFlush()
{
    if (fPrintToDebugLog.load())
    {
        fflush(logger_fileout.load());
    }
}

/** Get format string from VA_ARGS for error reporting */
template <typename... Args>
std::string FormatStringFromLogArgs(const char *fmt, const Args &...args)
{
    return fmt;
}


template <typename... Args>
bool error(const char *fmt, const Args &...args)
{
    LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}


template <typename... Args>
inline bool error(uint64_t ctgr, const char *fmt, const Args &...args)
{
    if (Logging::LogAcceptCategory(ctgr))
        LogPrintStr("ERROR: " + tfm::format(fmt, args...) + "\n");
    return false;
}

#endif // BITCOIN_LOGGING_H
