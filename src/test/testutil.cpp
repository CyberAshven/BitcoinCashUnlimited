// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "testutil.h"

#ifdef WIN32
#include <shlobj.h>
#endif

#include "fs.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"

fs::path GetTempPath() { return fs::temp_directory_path(); }
CMutableTransaction CreateRandomTx()
{
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = InsecureRand256();
    tx.vin[0].amount = 1 * CENT;
    tx.vin[0].scriptSig << OP_1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1 * CENT;
    tx.vout[0].scriptPubKey = GetScriptForDestination(key.GetPubKey().GetID());
    return tx;
}

// create a pay to public key hash script
CScript p2pkh(const CKeyID &dest)
{
    CScript script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(dest) << OP_EQUALVERIFY << OP_CHECKSIG;
    return script;
}


CScript p2sh(const CScriptID &dest)
{
    CScript script;

    script.clear();
    script << OP_HASH160 << ToByteVector(dest) << OP_EQUAL;
    return script;
}


CTransaction tx1x1(const COutPoint &utxo, const CScript &txo, CAmount amt)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].amount = amt;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript(); // you must sign if you want it signed
    tx.nLockTime = 0;
    return tx;
}

CTransaction tx1x2(const COutPoint &utxo, const CScript &txo, CAmount amt, const CScript &txo2, CAmount amt2)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].amount = amt + amt2;
    tx.vin[0].scriptSig = CScript(); // you must sign if you want it signed
    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vout[1].scriptPubKey = txo2;
    tx.vout[1].nValue = amt2;
    tx.nLockTime = 0;

    return tx;
}
CTransaction tx1x3(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CScript &txo2,
    CAmount amt2,
    const CScript &txo3,
    CAmount amt3)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].scriptSig = CScript(); // you must sign if you want it signed
    tx.vin[0].amount = amt + amt2 + amt3;
    tx.vout.resize(3);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vout[1].scriptPubKey = txo2;
    tx.vout[1].nValue = amt2;
    tx.vout[2].scriptPubKey = txo3;
    tx.vout[2].nValue = amt3;
    tx.nLockTime = 0;
    return tx;
}


CTransaction tx1x1(const COutPoint &utxo,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &prevOutScript,
    bool p2pkh)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = utxo;
    tx.vin[0].amount = amt;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevOutScript, tx, 0, sighashType, amt, 0);
    if (!key.SignSchnorr(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}

CTransaction tx1x1(const CTransaction &prevtx,
    int prevout,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    bool p2pkh)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetIdem(), prevout);
    tx.vin[0].amount = amt;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevtx.vout[prevout].scriptPubKey, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.SignSchnorr(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}

CTransaction tx1x1_p2sh_of_p2pkh(const CTransaction &prevtx,
    int prevout,
    const CScript &txo,
    CAmount amt,
    const CKey &key,
    const CScript &redeemScript)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetIdem(), prevout);
    tx.vin[0].amount = amt;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = txo;
    tx.vout[0].nValue = amt;
    tx.vin[0].scriptSig = CScript();
    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(redeemScript, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.SignSchnorr(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    tx.vin[0].scriptSig << ToByteVector(redeemScript);

    return tx;
}


CTransaction tx1x2(const CTransaction &prevtx,
    int prevout,
    const CScript &txo0,
    CAmount amt0,
    const CScript &txo1,
    CAmount amt1,
    const CKey &key,
    bool p2pkh)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(prevtx.GetIdem(), prevout);
    tx.vin[0].scriptSig = CScript();
    tx.vin[0].amount = amt0 + amt1;
    tx.vout.resize(2);
    tx.vout[0].scriptPubKey = txo0;
    tx.vout[0].nValue = amt0;
    tx.vout[1].scriptPubKey = txo1;
    tx.vout[1].nValue = amt1;

    tx.nLockTime = 0;

    unsigned int sighashType = SIGHASH_ALL | SIGHASH_FORKID;
    std::vector<unsigned char> vchSig;
    uint256 hash = SignatureHash(prevtx.vout[prevout].scriptPubKey, tx, 0, sighashType, prevtx.vout[prevout].nValue, 0);
    if (!key.SignSchnorr(hash, vchSig))
    {
        assert(0);
    }
    vchSig.push_back((unsigned char)sighashType);
    tx.vin[0].scriptSig << vchSig;
    if (p2pkh)
    {
        tx.vin[0].scriptSig << ToByteVector(key.GetPubKey());
    }

    return tx;
}
