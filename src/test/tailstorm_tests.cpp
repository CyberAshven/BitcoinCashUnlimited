#include "tailstorm/tailstorm.h"
#include "test/test_bitcoin.h"
#include <boost/math/distributions/gamma.hpp>
#include <boost/test/unit_test.hpp>
#include <iostream>

BOOST_FIXTURE_TEST_SUITE(tailstorm_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_dag_score)
{
    /* n1 -> n2
     *  |
     *  ---> n3 -> n4
     *  Scores:
     *      n4: 1
     *      n3: 1+ 2*1 = 3
     *      n2: 1
     *      n1: 1 + 3*(3+1) = 13
     */
    int anticipatedTotalScore = 18;
    // root node
    CSubBlock subblock1;
    CDagNode *node1 = new CDagNode(subblock1);
    // two descendants, which are siblings
    CSubBlock subblock2;
    CDagNode *node2 = new CDagNode(subblock2);
    node1->AddDescendant(node2);
    node2->AddAncestor(node1);
    CSubBlock subblock3;
    CDagNode *node3 = new CDagNode(subblock3);
    node1->AddDescendant(node3);
    node3->AddAncestor(node1);
    // one descendant, which is child of one sibling
    CSubBlock subblock4;
    CDagNode *node4 = new CDagNode(subblock4);
    node3->AddDescendant(node4);
    node4->AddAncestor(node3);

    // create dag
    CTailstormDag dag(0, node1);
    dag.Insert(node2);
    dag.Insert(node3);
    dag.Insert(node4);

    BOOST_CHECK(dag.score == anticipatedTotalScore);
}

BOOST_AUTO_TEST_CASE(arith_uint256_sanity)
{
    unsigned int nBits = 545259519;
    arith_uint256 a;
    a.SetCompact(nBits);
    arith_uint256 b;
    b.SetCompact(nBits);
    b /= 1000;
    arith_uint256 c;
    a.SetCompact(nBits);
    c = ~c;
    c *= 1000;
    c = ~c;

    BOOST_CHECK(a > b);
    BOOST_CHECK(a > c);
}

BOOST_AUTO_TEST_CASE(gamma_sanity_check)
{
    // The median of the exponential distribution with mean 1 should be ln(2)
    boost::math::gamma_distribution<> expon(1,1);
    BOOST_CHECK(quantile(expon, 0.5) == std::log(2));

    // The quantile of the density of a gamma at its mean should be equal to k*scale_parameter
    uint8_t k = 3;
    arith_uint256 scale = arith_uint256(1e6);
    boost::math::gamma_distribution<> tailstorm_gamma(k, scale.getdouble());
    BOOST_CHECK(quantile(tailstorm_gamma, cdf(tailstorm_gamma, mean(tailstorm_gamma))) == k*scale.getdouble());
}

BOOST_AUTO_TEST_CASE(test_scaling_gamma, *boost::unit_test::tolerance(0.000001))
{
    uint8_t k = 3;
    arith_uint256 scale = arith_uint256(1e6);
    arith_uint256 scaler = arith_uint256(13);
    arith_uint256 scaled_scale = scale / scaler;
    boost::math::gamma_distribution<> tailstorm_gamma(k, scale.getdouble());
    boost::math::gamma_distribution<> tailstorm_gamma_scaled(k, scaled_scale.getdouble());

    double mean1 = mean(tailstorm_gamma);
    double mean2 = scaler.getdouble()*mean(tailstorm_gamma_scaled);
    double relative_error = std::abs(mean1 - mean2) / mean1;
}

BOOST_AUTO_TEST_CASE(test_update_tx_lists)
{
    /* n1 -> n2
     */
    // root node
    CSubBlockRef subref1 = std::make_shared<CSubBlock>();
    subref1->nNonce = 1;
    // one descendant
    CSubBlockRef subref2 = std::make_shared<CSubBlock>();
    subref1->nNonce = 2;
    CDagNode *node2 = new CDagNode(*subref2);
    CDagNode *node1 = new CDagNode(*subref1);
    node1->AddDescendant(node2);
    node2->AddAncestor(node1);

    // add txs to subblocks
    CMutableTransaction mtx11;
    mtx11.vin.resize(1);
    mtx11.vin[0].prevout.n = 11;
    CTransactionRef tx11 = std::make_shared<const CTransaction>(mtx11);
    CMutableTransaction mtx12;
    mtx12.vin.resize(1);
    mtx12.vin[0].prevout.n = 12;
    CTransaction _tx12(mtx12);
    CTransactionRef tx12 = std::make_shared<const CTransaction>(mtx12);
    subref1->vtx.push_back(tx11);
    subref1->vtx.push_back(tx12);

    CMutableTransaction mtx21;
    mtx21.vin.resize(1);
    mtx21.vin[0].prevout.n = 21;
    CTransaction _tx21(mtx21);
    CTransactionRef tx21 = std::make_shared<const CTransaction>(mtx21);
    CMutableTransaction mtx22;
    mtx22.vin.resize(1);
    mtx22.vin[0].prevout.n = 22;
    CTransactionRef tx22 = std::make_shared<const CTransaction>(mtx22);
    subref2->vtx.push_back(tx21);
    subref2->vtx.push_back(tx22);

    // form block
    CTailstormBlock block;
    block.vdag.push_back(subref1);
    block.vdag.push_back(subref2);
    block.UpdateTxLists();

    BOOST_CHECK(block.vtx.size() == 5);

    // validate decoded subblock tx info
    std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > subblockTxListMap = block.DecodeTxLists();
    BOOST_CHECK(subblockTxListMap[subref1->GetHash()].second[0] == tx11);
    BOOST_CHECK(subblockTxListMap[subref1->GetHash()].second[1] == tx12);
    BOOST_CHECK(subblockTxListMap[subref2->GetHash()].second[0] == tx21);
    BOOST_CHECK(subblockTxListMap[subref2->GetHash()].second[1] == tx22);
}

BOOST_AUTO_TEST_SUITE_END()
