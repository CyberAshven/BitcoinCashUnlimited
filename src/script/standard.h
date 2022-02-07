// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include "consensus/grouptokens.h"
#include "script/interpreter.h"
#include "uint256.h"

#include <boost/variant.hpp>

#include <stdint.h>

class CKeyID;
class CScript;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript &in);
    CScriptID(const uint160 &in) : uint160(in) {}
};

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_CLTV,
    TX_LABELPUBLIC,
    TX_NULL_DATA,
    TX_GRP_PUBKEYHASH,
    TX_GRP_SCRIPTHASH
};

class CNoDestination
{
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination: no destination set
 *  * CKeyID: TX_PUBKEYHASH destination
 *  * CScriptID: TX_SCRIPTHASH destination
 *  A CTxDestination is the internal data type encoded in a bitcoin address
 */
typedef boost::variant<CNoDestination, CKeyID, CScriptID> CTxDestination;

const char *GetTxnOutputType(txnouttype t);

bool ExtendedSolver(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<std::vector<unsigned char> > &vSolutionsRet,
    CGroupTokenInfo &grp);
bool Solver(const CScript &scriptPubKey, txnouttype &typeRet, std::vector<std::vector<unsigned char> > &vSolutionsRet);
bool ExtractDestination(const CScript &scriptPubKey, CTxDestination &addressRet);
bool ExtractDestinationAndType(const CScript &scriptPubKey, CTxDestination &addressRet, txnouttype &whichType);
bool ExtractDestinations(const CScript &scriptPubKey,
    txnouttype &typeRet,
    std::vector<CTxDestination> &addressRet,
    int &nRequiredRet);

const char *GetTxnOutputType(txnouttype t);
bool IsValidDestination(const CTxDestination &dest);

CScript GetScriptForDestination(const CTxDestination &dest);
CScript GetScriptForRawPubKey(const CPubKey &pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey> &keys);
CScript GetScriptForFreeze(CScriptNum nLockTime, const CPubKey &pubKey);
CScript GetScriptLabelPublic(const std::string &labelPublic);


#endif // BITCOIN_SCRIPT_STANDARD_H
