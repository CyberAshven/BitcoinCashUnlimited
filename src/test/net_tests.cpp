// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addrman.h"
#include "chainparams.h"
#include "hashwrapper.h"
#include "net.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <string>

using namespace std;

class CAddrManSerializationMock : public CAddrMan
{
public:
    virtual void Serialize(CDataStream &s) const = 0;

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        insecure_rand = FastRandomContext(true);
    }
};

class CAddrManUncorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const { CAddrMan::Serialize(s); }
};

class CAddrManCorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const
    {
        // Produces corrupt output that claims addrman has 20 addrs when it only has one addr.
        unsigned char nVersion = 1;
        s << nVersion;
        s << uint8_t(32);
        s << nKey;
        s << 10; // nNew
        s << 10; // nTried

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
        s << nUBuckets;

        CAddress addr = CAddress(CService("252.1.1.1", 7777));
        CAddrInfo info = CAddrInfo(addr, CNetAddr("252.2.2.2"));
        s << info;
    }
};

CDataStream AddrmanToStream(CAddrManSerializationMock &_addrman)
{
    CDataStream ssPeersIn(SER_DISK, CLIENT_VERSION);
    ssPeersIn << FLATDATA(Params().MessageStart());
    ssPeersIn << _addrman;
    std::string str = ssPeersIn.str();
    std::vector<uint8_t> vchData(str.begin(), str.end());
    return CDataStream(vchData, SER_DISK, CLIENT_VERSION);
}

BOOST_FIXTURE_TEST_SUITE(net_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(caddrdb_read)
{
    CAddrManUncorrupted addrmanUncorrupted;
    addrmanUncorrupted.MakeDeterministic();

    CService addr1 = CService("250.7.1.1", 8333);
    CService addr2 = CService("250.7.2.2", 9999);
    CService addr3 = CService("250.7.3.3", 9999);

    // Add three addresses to new table.
    addrmanUncorrupted.Add(CAddress(addr1), CService("252.5.1.1", 8333));
    addrmanUncorrupted.Add(CAddress(addr2), CService("252.5.1.1", 8333));
    addrmanUncorrupted.Add(CAddress(addr3), CService("252.5.1.1", 8333));

    // Test that the de-serialization does not throw an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanUncorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;

    BOOST_CHECK(addrman1.size() == 0);
    try
    {
        uint8_t pchMsgTmp[4];
        ssPeers1 >> FLATDATA(pchMsgTmp);
        ssPeers1 >> addrman1;
    }
    catch (const std::exception &e)
    {
        exceptionThrown = true;
    }

    BOOST_CHECK(addrman1.size() == 3);
    BOOST_CHECK(exceptionThrown == false);

    // Test that CAddrDB::Read creates an addrman with the correct number of addrs.
    CDataStream ssPeers2 = AddrmanToStream(addrmanUncorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    adb.Read(addrman2, ssPeers2);
    BOOST_CHECK(addrman2.size() == 3);
}


BOOST_AUTO_TEST_CASE(caddrdb_read_corrupted)
{
    CAddrManCorrupted addrmanCorrupted;
    addrmanCorrupted.MakeDeterministic();

    // Test that the de-serialization of corrupted addrman throws an exception.
    CDataStream ssPeers1 = AddrmanToStream(addrmanCorrupted);
    bool exceptionThrown = false;
    CAddrMan addrman1;
    BOOST_CHECK(addrman1.size() == 0);
    try
    {
        uint8_t pchMsgTmp[4];
        ssPeers1 >> FLATDATA(pchMsgTmp);
        ssPeers1 >> addrman1;
    }
    catch (const std::exception &e)
    {
        exceptionThrown = true;
    }
    // Even through de-serialization failed addrman is not left in a clean state.
    BOOST_CHECK(addrman1.size() == 1);
    BOOST_CHECK(exceptionThrown);

    // Test that CAddrDB::Read leaves addrman in a clean state if de-serialization fails.
    CDataStream ssPeers2 = AddrmanToStream(addrmanCorrupted);

    CAddrMan addrman2;
    CAddrDB adb;
    BOOST_CHECK(addrman2.size() == 0);
    adb.Read(addrman2, ssPeers2);
    BOOST_CHECK(addrman2.size() == 0);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    SOCKET hSocket = INVALID_SOCKET;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest = "";
    bool fInboundIn = false;

    // Test that fFeeler is false by default.
    std::unique_ptr<CNode> pnode1(new CNode(hSocket, addr, pszDest, fInboundIn));
    BOOST_CHECK(pnode1->fInbound == false);
    BOOST_CHECK(pnode1->fFeeler == false);

    fInboundIn = true;
    std::unique_ptr<CNode> pnode2(new CNode(hSocket, addr, pszDest, fInboundIn));
    BOOST_CHECK(pnode2->fInbound == true);
    BOOST_CHECK(pnode2->fFeeler == false);

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "0.0.0.0");

    // IPv4, INADDR_NONE
    BOOST_REQUIRE(LookupHost("255.255.255.255", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "255.255.255.255");

    // IPv4, casual
    BOOST_REQUIRE(LookupHost("12.34.56.78", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "12.34.56.78");

    // IPv6, in6addr_any
    BOOST_REQUIRE(LookupHost("::", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "::");

    // IPv6, casual
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // TORv2
    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "6hzph5hv6337r6p2.onion");

    // TORv3
    const char *torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(
        !addr.SetSpecial(std::string{"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1) {
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd87d87eeb43f1f2f3f4f5f6f7f8f9fa");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2) {
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("6hzph5hv6337r6p2.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "030af1f2f3f4f5f6f7f8f9fa");
    s.clear();

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2) {
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    s << MakeSpan(ParseHex("01"          // network type (IPv4)
                           "04"          // address length
                           "01020304")); // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << MakeSpan(ParseHex("01"      // network type (IPv4)
                           "04"      // address length
                           "0102")); // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << MakeSpan(ParseHex("01"          // network type (IPv4)
                           "05"          // address length
                           "01020304")); // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << MakeSpan(ParseHex("01"          // network type (IPv4)
                           "fd0102"      // address length (513 as CompactSize)
                           "01020304")); // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                           "10"                                  // address length
                           "0102030405060708090a0b0c0d0e0f10")); // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                           "10"                                  // address length
                           "fd6b88c08724ca978112ca1bbdcafac2")); // address: 0xfd + sha256("bitcoin")[0:5] +
                                                                 // sha256(name)[0:10]
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << MakeSpan(ParseHex("02"    // network type (IPv6)
                           "04"    // address length
                           "00")); // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                           "10"                                  // address length
                           "00000000000000000000ffff01020304")); // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << MakeSpan(ParseHex("02"                                  // network type (IPv6)
                           "10"                                  // address length
                           "fd87d87eeb430102030405060708090a")); // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv2.
    s << MakeSpan(ParseHex("03"                      // network type (TORv2)
                           "0a"                      // address length
                           "f1f2f3f4f5f6f7f8f9fa")); // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "6hzph5hv6337r6p2.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv2, with bogus length.
    s << MakeSpan(ParseHex("03"    // network type (TORv2)
                           "07"    // address length
                           "00")); // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv2 address with length 7 (should be 10)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid TORv3.
    s << MakeSpan(ParseHex("04"                               // network type (TORv3)
                           "20"                               // address length
                           "79bcc625184b05194975c28b66b66b04" // address
                           "69f7f6556fb1ac3189a79b40dda32f1f"));
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << MakeSpan(ParseHex("04" // network type (TORv3)
                           "00" // address length
                           "00" // address
                           ));
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << MakeSpan(ParseHex("05"                               // network type (I2P)
                           "20"                               // address length
                           "a2894dabaec08c0051a481a6dac88b64" // address
                           "f98232ae42d4b6fd2fa81952dfe36a87"));
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << MakeSpan(ParseHex("05" // network type (I2P)
                           "03" // address length
                           "00" // address
                           ));
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << MakeSpan(ParseHex("06"                               // network type (CJDNS)
                           "10"                               // address length
                           "fc000001000200030004000500060007" // address
                           ));
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << MakeSpan(ParseHex("06" // network type (CJDNS)
                           "01" // address length
                           "00" // address
                           ));
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << MakeSpan(ParseHex("aa"             // network type (unknown)
                           "fe00000002"     // address length (CompactSize's MAX_SIZE)
                           "01020304050607" // address
                           ));
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << MakeSpan(ParseHex("aa"       // network type (unknown)
                           "04"       // address length
                           "01020304" // address
                           ));
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << MakeSpan(ParseHex("aa" // network type (unknown)
                           "00" // address length
                           ""   // address
                           ));
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

BOOST_AUTO_TEST_CASE(test_getSubVersionEB) {
    BOOST_CHECK_EQUAL(getSubVersionEB(13800000000), "13800.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(3800000000), "3800.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(14000000), "14.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(1540000), "1.5");
    BOOST_CHECK_EQUAL(getSubVersionEB(1560000), "1.5");
    BOOST_CHECK_EQUAL(getSubVersionEB(210000), "0.2");
    BOOST_CHECK_EQUAL(getSubVersionEB(10000), "0.0");
    BOOST_CHECK_EQUAL(getSubVersionEB(0), "0.0");
}

BOOST_AUTO_TEST_CASE(test_FormatSubVersion) {
    BOOST_CHECK_EQUAL(FormatSubVersion("Test", 1, std::vector<std::string>{"comment1", "comment2", "comment3"}), "/Test:0.0.0.1(comment1; comment2; comment3)/");
    BOOST_CHECK_EQUAL(FormatSubVersion("Test 2", 12, std::vector<std::string>{"comment1"}), "/Test 2:0.0.0.12(comment1)/");
    BOOST_CHECK_EQUAL(FormatSubVersion("Test 3", 123, std::vector<std::string>{"comment1", "comment2"}), "/Test 3:0.0.1.23(comment1; comment2)/");
    BOOST_CHECK_EQUAL(FormatSubVersion("Test 4", 1234, std::vector<std::string>{"comment1", "comment2", "comment3"}), "/Test 4:0.0.12.34(comment1; comment2; comment3)/");
    BOOST_CHECK_EQUAL(FormatSubVersion("Test 5", 1234567890, std::vector<std::string>{"comment1", "comment2", "comment3"}), "/Test 5:1234.56.78.90(comment1; comment2; comment3)/");
    BOOST_CHECK_EQUAL(FormatSubVersion("", 0, std::vector<std::string>{}), "/:0.0.0/");
}

BOOST_AUTO_TEST_CASE(test_userAgent) {
    NetTestConfig config;

    config.SetExcessiveBlockSize(8000000);
    const std::string uacomment = "A very nice comment";
    gArgs.ForceSetMultiArg("-uacomment", uacomment);

    const std::string versionMessage =
        "/Bitcoin Cash Node:" + std::to_string(CLIENT_VERSION_MAJOR) + "." +
        std::to_string(CLIENT_VERSION_MINOR) + "." +
        std::to_string(CLIENT_VERSION_REVISION) + "(EB8.0; " + uacomment + ")/";

    const std::string versionMessage_strprintf =
        strprintf("/Bitcoin Cash Node:%d.%d.%d(EB8.0; %s)/", CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_REVISION, uacomment);

    BOOST_CHECK_EQUAL(versionMessage, versionMessage_strprintf); // verify our test methodology is sound - std::to_string is locale-dependent
    BOOST_CHECK_EQUAL(userAgent(config), versionMessage);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network) {
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), true);

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);

    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), false);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), false);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), false);

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);

    BOOST_CHECK_EQUAL(IsReachable(NET_IPV4), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_IPV6), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_ONION), true);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal) {
    BOOST_CHECK_EQUAL(IsReachable(NET_UNROUTABLE), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_INTERNAL), true);

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    // Ignored for both networks
    BOOST_CHECK_EQUAL(IsReachable(NET_UNROUTABLE), true);
    BOOST_CHECK_EQUAL(IsReachable(NET_INTERNAL), true);
}

CNetAddr UtilBuildAddress(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4) {
    uint8_t ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    // initialize the memory block
    memset(&sa, 0, sizeof(sockaddr_in));
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr) {
    // 1.1.1.1
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001);

    SetReachable(NET_IPV4, true);
    BOOST_CHECK_EQUAL(IsReachable(addr), true);

    SetReachable(NET_IPV4, false);
    BOOST_CHECK_EQUAL(IsReachable(addr), false);

    // get()
    {
        CNodeRef ref1(pnode1.get());
        CNodeRef ref2;
        BOOST_CHECK(ref1.get() == pnode1.get());
        BOOST_CHECK(ref2.get() == nullptr);
    }

    // Plain constructor and copy constructor
    {
        CNodeRef ref1(pnode1.get());
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);

        {
            CNodeRef ref2(ref1);
            BOOST_CHECK_EQUAL(pnode1->nRefCount, 2);
        }

        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
    }
    BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);

    // Assignment operator
    {
        CNodeRef ref1;

        ref1 = pnode1.get();
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
        ref1 = ref1;
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 1);
        ref1 = nullptr;
        BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);
    }
    BOOST_CHECK_EQUAL(pnode1->nRefCount, 0);
}

BOOST_AUTO_TEST_CASE(test_userAgent)
{
    const std::vector<std::string> uacomments{"A very nice comment"};
    int temp = 0;
    int *ptemp = &temp;
    std::string arch = (sizeof(ptemp) == 4) ? "32bit" : "64bit";
    mapArgs["-uacomment"] = uacomments[0];
    std::string client_name(CLIENT_NAME);

    std::string versionMessage = "/" + client_name + ":" + std::to_string(CLIENT_VERSION_MAJOR) + "." +
                                 std::to_string(CLIENT_VERSION_MINOR) + "." + std::to_string(CLIENT_VERSION_REVISION);

    if (std::to_string(CLIENT_VERSION_BUILD) != "0")
    {
        versionMessage = versionMessage + "." + std::to_string(CLIENT_VERSION_BUILD);
    }
    versionMessage = versionMessage + "(" + uacomments[0] + "; " + arch + ")/";

    BOOST_CHECK_EQUAL(FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments), versionMessage);
}

BOOST_AUTO_TEST_SUITE_END()
