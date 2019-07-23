// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2017-2018 The cruZado developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime     = nTime;
    genesis.nBits     = nBits;
    genesis.nNonce    = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion  = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'cruZado' + blake2s(b'[Mega-Sena] Resultado Concurso 2170 (17/07/2019) 10 - 21 - 24 - 36 - 38 - 51').hexdigest()
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "cruZado835baacb6ed945f9eddde740f19f117bb7ca685d439943160bedeee707c773f8";
    const CScript genesisOutputScript = CScript() << ParseHex("0479180e0a45ad8c5e4b52356bdef7c4fee30ed25af72af20d6e29ccc838ab9950eacf68d981ee97150239e0fdb2d00a2cce89ea9ea7d2d1d7f2bc9771630a9d2d") << OP_CHECKSIG;

    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "CRZ";
        bip44CoinType = 221; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        const size_t N_1 = 200, K_1 = 9;
        const size_t N_2 = 144, K_2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_1, K_1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_2, K_2));
        consensus.nEquihashN_1 = N_1;
        consensus.nEquihashK_1 = K_1;
        consensus.nEquihashN_2 = N_2;
        consensus.nEquihashK_2 = K_2;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 190000;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 190000;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170009;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.nEquihashForkHeight = 1;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000003cbab61c14c");

        pchMessageStart[0] = 0x7b;
        pchMessageStart[1] = 0x46;
        pchMessageStart[2] = 0x8a;
        pchMessageStart[3] = 0xd6;
        vAlertPubKey = ParseHex("048c64efd9e320f8dc6ab14f3e2c674877fe1b027f62afaffdd46ee4a191b3be90dd5a3bf8c7f6b2205dbde788793e97a645a16c2d8bede3dca0182dfc3cc15137");

        nDefaultPort = 30333;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(
            1563580800,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000002a"),
            ParseHex("001c1635613589bfb1d3a30f4a26589ba7721ee6c323e7fc4bb66bbcc76a5ab9854d55eaea71f5746c1b06ae287a4419dd159553629ed4ee88ad61cbd5501f22d0ce904da5c5a98062f2cbc89f2bf17bb8ff63f903b3e58cc8f814f3d02a41264c122f26bea1967d5f0ba4da2a965fee8f9da7a5975ab11052039e1ed48108cde40c97888641a993d1cb4360484c83458c47a70b82abd329caa665f3e9b2b1b1204f0b04f118bb51005e790b1a5673cf5c44357592d4d4a17bd930669c1aa77a594814392d32075243a3683f81e87bb34a600a306389b956406b4aeb24161c56e8720dda38e15919dac2a56b4d51fcab49b42a45d7a8c9f58ff939a706ed53085bec76ed8c6924363af90dff950e9fa588280c3f1d1325c961b05e23b48ddc38fe4621ddf46120dd7c9be7ae46459b22c82becc971f6b7bb3a9b173a2e163acc64265fcec5e5c4d83a1c8e7707396fae0423f47d4f0476754483e96e105debc7b58d9eb516390c2d066ab06891d346d616e33f484f5d221e950609d29dfb25f11601a1693246e3361ffdaf220eabaf0dd0957625a5468f907f32bbd0636821c07a15926b09fdd0b1fa173de3d57b00f7138bfb744e92d88ae912de65056aeba2e1794d34633b59b66689c2749626128609f05feb970d696911f3759d6d50bd226869ac29f34e0bf1d0ee38fa9a43d38b557b458fd6dea7cb08fe5b7ef489104e7f96a0aced6bf896a1991908f5213d0ed982a244edc114ec25d6f287c348857ee98313458221105c98bbc184355771e015bde4b1dd12791b0f5667c2138beb774e0306ec617d71260575c46f103bfc55afb3ba67c046931a8c723ebd28553b14b11e5d0a839e4a5ec6a0cf04b35027f4b2d2db3a22a91d90b7cf0aad1a9184e24529c7b242bd659698896b55ca8b8452ed871dd9db2c047f729d2b45cd5a967f00d9247efea442618d3030a671a3f744bbcbe624e20d4bc50bd6204d8348efc2864fba08dcd8e973d31a081ed8cbf66409213d58e8603c719bde258d5f3d4451f95da081bad38fea9036f5b2e638a6a3edf794f4246c07432ea2b65372fbb2ad73f62420b49a9e317745eadfc4e22c583fe7abc50871eccd7733b0bda7e726c88d6f0958dfd3a69272c8b258cabce8bf770d3e4ef3ed4ab65df1db4f8926ebf3745bfe5cb3f3481e097180f61505fd634a627181cbd7fd02233118f071285c85dc5cca4faf14ba77e737e88d1257ac1f42fa0d03f87748c38215a88f16c4f05f64ce4fd67cc2d40d943f966255d1e51478546acacab1e565e47753bd0e9f06100d5112f3bbc9e2a0275f7ca631f97827645d33fcd2a1b648d3dea2a9a80a7cf77ad07d3ab09814af94e00d905fc6eedb52ccc02ab50a6083fcc1b62b30f77f2de12fcb740a634758f5b7da273755da95036beb1f6c4413e221fec3f2f4ff037f61fa3b97450e0538a44d5595cd2fd5aa0be3f58de70d39dc21c73118244f2a9785dd482616748f60d7bf14073bce1e525c9bcc789c0463e5ec591a917d4072e1717e60f2178a4a37ff5a0cb387f82370a91ef6694a0830d54d2cf78699a69badc7e0b542d0ef624974b76eac46c5267f9fc7a5165f46d969c3ecda620271f74ad7d0bf38a22e50fa733a61ced0660a1f3e04933d5a1bfd8416e17ed46958ca1afa03a26a3a99a049fbfa3edeca1fe456e281dee3898240f26ec3f2c78f3c23db30a9219f2efdc30afbea863117f6c34e6e5edf0d5878627faef522aa28208172af9b4dfbe40c4711f858cfa92648a248621462ed414a54d3e4572b85a7e5f49cbd733eccd35b6c531f878d78167c4f15f23ce3dee066309e15e41a99f4b6d76793493abc49bcdc4d8a481958c07c91e8164e89098fc8b4f8d7fbde3dec1c0181"),
            0x1f07ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();

        //printf("hashGenesisBlock = uint256(\"0x%s\");\n", genesis.GetHash().ToString().c_str());
        //printf("hashMerkleRoot = uint256(\"0x%s\");\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("last block height for founders = %d\n", consensus.GetLastFoundersRewardBlockHeight());

        assert(genesis.hashMerkleRoot == uint256S("0x7a80676ed85e50411f14a94276b58ac6cc674d7909f3b038ddb583fbdd35a579"));
        assert(consensus.hashGenesisBlock == uint256S("0x000496e5592bd7ef7af832a7e84d6b624417e41f5d8886e14cabf51050d2c64f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("cruzado.org", "dnsseed.cruzado.org")); // cruZado

        // guarantees the first 2 characters, when base58 encoded, are "C1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB3};
        // guarantees the first 2 characters, when base58 encoded, are "C3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xB8};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};	// xpub
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};	// xprv
        // guarantees the first 2 characters, when base58 encoded, are "zm"
        base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x16,0xAA};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "MK"
        base58Prefixes[ZCSPENDING_KEY]     = {0x89,0x64};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1563580800,     // * UNIX timestamp of last checkpoint block
            1,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            0            // * estimated number of transactions per day after checkpoint
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 313335;
        // nSproutValuePoolCheckpointBalance = 50924382539501;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("0x000496e5592bd7ef7af832a7e84d6b624417e41f5d8886e14cabf51050d2c64f");
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TCZ";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        const size_t N_1 = 200, K_1 = 9;
        const size_t N_2 = 144, K_2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_1, K_1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_2, K_2));
        consensus.nEquihashN_1 = N_1;
        consensus.nEquihashK_1 = K_1;
        consensus.nEquihashN_2 = N_2;
        consensus.nEquihashK_2 = K_2;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 4000;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 4000;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.nEquihashForkHeight = 1;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000f1eb9b");

        pchMessageStart[0] = 0x1a;
        pchMessageStart[1] = 0xc7;
        pchMessageStart[2] = 0xd9;
        pchMessageStart[3] = 0x71;

        vAlertPubKey = ParseHex("04a820f404086f812ba6effc156bc7fba4b3248e002be5f44de573301805263700081df39e0e84d3aead611c2da1f89cce353cf2c6643c14651e3f91acdba255f3");

        nDefaultPort = 40333;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(
            1563580800,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000002a"),
            ParseHex("001c1635613589bfb1d3a30f4a26589ba7721ee6c323e7fc4bb66bbcc76a5ab9854d55eaea71f5746c1b06ae287a4419dd159553629ed4ee88ad61cbd5501f22d0ce904da5c5a98062f2cbc89f2bf17bb8ff63f903b3e58cc8f814f3d02a41264c122f26bea1967d5f0ba4da2a965fee8f9da7a5975ab11052039e1ed48108cde40c97888641a993d1cb4360484c83458c47a70b82abd329caa665f3e9b2b1b1204f0b04f118bb51005e790b1a5673cf5c44357592d4d4a17bd930669c1aa77a594814392d32075243a3683f81e87bb34a600a306389b956406b4aeb24161c56e8720dda38e15919dac2a56b4d51fcab49b42a45d7a8c9f58ff939a706ed53085bec76ed8c6924363af90dff950e9fa588280c3f1d1325c961b05e23b48ddc38fe4621ddf46120dd7c9be7ae46459b22c82becc971f6b7bb3a9b173a2e163acc64265fcec5e5c4d83a1c8e7707396fae0423f47d4f0476754483e96e105debc7b58d9eb516390c2d066ab06891d346d616e33f484f5d221e950609d29dfb25f11601a1693246e3361ffdaf220eabaf0dd0957625a5468f907f32bbd0636821c07a15926b09fdd0b1fa173de3d57b00f7138bfb744e92d88ae912de65056aeba2e1794d34633b59b66689c2749626128609f05feb970d696911f3759d6d50bd226869ac29f34e0bf1d0ee38fa9a43d38b557b458fd6dea7cb08fe5b7ef489104e7f96a0aced6bf896a1991908f5213d0ed982a244edc114ec25d6f287c348857ee98313458221105c98bbc184355771e015bde4b1dd12791b0f5667c2138beb774e0306ec617d71260575c46f103bfc55afb3ba67c046931a8c723ebd28553b14b11e5d0a839e4a5ec6a0cf04b35027f4b2d2db3a22a91d90b7cf0aad1a9184e24529c7b242bd659698896b55ca8b8452ed871dd9db2c047f729d2b45cd5a967f00d9247efea442618d3030a671a3f744bbcbe624e20d4bc50bd6204d8348efc2864fba08dcd8e973d31a081ed8cbf66409213d58e8603c719bde258d5f3d4451f95da081bad38fea9036f5b2e638a6a3edf794f4246c07432ea2b65372fbb2ad73f62420b49a9e317745eadfc4e22c583fe7abc50871eccd7733b0bda7e726c88d6f0958dfd3a69272c8b258cabce8bf770d3e4ef3ed4ab65df1db4f8926ebf3745bfe5cb3f3481e097180f61505fd634a627181cbd7fd02233118f071285c85dc5cca4faf14ba77e737e88d1257ac1f42fa0d03f87748c38215a88f16c4f05f64ce4fd67cc2d40d943f966255d1e51478546acacab1e565e47753bd0e9f06100d5112f3bbc9e2a0275f7ca631f97827645d33fcd2a1b648d3dea2a9a80a7cf77ad07d3ab09814af94e00d905fc6eedb52ccc02ab50a6083fcc1b62b30f77f2de12fcb740a634758f5b7da273755da95036beb1f6c4413e221fec3f2f4ff037f61fa3b97450e0538a44d5595cd2fd5aa0be3f58de70d39dc21c73118244f2a9785dd482616748f60d7bf14073bce1e525c9bcc789c0463e5ec591a917d4072e1717e60f2178a4a37ff5a0cb387f82370a91ef6694a0830d54d2cf78699a69badc7e0b542d0ef624974b76eac46c5267f9fc7a5165f46d969c3ecda620271f74ad7d0bf38a22e50fa733a61ced0660a1f3e04933d5a1bfd8416e17ed46958ca1afa03a26a3a99a049fbfa3edeca1fe456e281dee3898240f26ec3f2c78f3c23db30a9219f2efdc30afbea863117f6c34e6e5edf0d5878627faef522aa28208172af9b4dfbe40c4711f858cfa92648a248621462ed414a54d3e4572b85a7e5f49cbd733eccd35b6c531f878d78167c4f15f23ce3dee066309e15e41a99f4b6d76793493abc49bcdc4d8a481958c07c91e8164e89098fc8b4f8d7fbde3dec1c0181"),
            0x1f07ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();

        //printf("hashGenesisBlock = uint256(\"0x%s\");\n", genesis.GetHash().ToString().c_str());
        //printf("hashMerkleRoot = uint256(\"0x%s\");\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("last block height for founders = %d\n", consensus.GetLastFoundersRewardBlockHeight());

        assert(genesis.hashMerkleRoot == uint256S("0x7a80676ed85e50411f14a94276b58ac6cc674d7909f3b038ddb583fbdd35a579"));
        assert(consensus.hashGenesisBlock == uint256S("0x000496e5592bd7ef7af832a7e84d6b624417e41f5d8886e14cabf51050d2c64f"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("cruzado.org", "dnsseed.cruzado.org")); // cruZado

        // guarantees the first 2 characters, when base58 encoded, are "T1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x0E,0xA4};
        // guarantees the first 2 characters, when base58 encoded, are "T3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x0E,0xA9};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};	// tpub
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};	// tprv
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "TK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xB1,0xF8};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1563580800,  // * UNIX timestamp of last checkpoint block
            1,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 313335;
        // nSproutValuePoolCheckpointBalance = 50924382539501;
        fZIP209Enabled = true;
        hashSproutValuePoolCheckpointBlock = uint256S("0x000496e5592bd7ef7af832a7e84d6b624417e41f5d8886e14cabf51050d2c64f");
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "RCZ";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        const size_t N_1 = 48, K_1 = 5;
        const size_t N_2 = 96, K_2 = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_1, K_1));
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N_2, K_2));
        consensus.nEquihashN_1 = N_1;
        consensus.nEquihashK_1 = K_1;
        consensus.nEquihashN_2 = N_2;
        consensus.nEquihashK_2 = K_2;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170004;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nProtocolVersion = 170008;
        consensus.vUpgrades[Consensus::UPGRADE_BLOSSOM].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.nEquihashForkHeight = 1;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xf0;
        pchMessageStart[1] = 0x0b;
        pchMessageStart[2] = 0xba;
        pchMessageStart[3] = 0x8c;

        nDefaultPort = 49444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1560580800,
            uint256S("0x00000000000000000000000000000000000000000000000000000000000000004"),
            ParseHex("1363f6dd55efa1e16f1ad29d5834ae21e7a122a8df91b38751b9e27fdde6dedb56ff5ff8"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();

        //printf("hashGenesisBlock = uint256(\"0x%s\");\n", genesis.GetHash().ToString().c_str());
        //printf("hashMerkleRoot = uint256(\"0x%s\");\n", genesis.hashMerkleRoot.ToString().c_str());

        assert(genesis.hashMerkleRoot == uint256S("0x7a80676ed85e50411f14a94276b58ac6cc674d7909f3b038ddb583fbdd35a579"));
        assert(consensus.hashGenesisBlock == uint256S("0x0463aea60f1bd4a01efea9954b4bc218530f82ee076b159219b7a851fcbd8c1b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x0E,0xA4};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x0E,0xA9};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRESS]  = {0x16,0xB6};
        base58Prefixes[ZCSPENDING_KEY]     = {0xB1,0xF8};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1563580800,
            1,
            0
        };
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

unsigned int CChainParams::EquihashSolutionWidth(int height) const
{
    return EhSolutionWidth(consensus.EquihashN(height), consensus.EquihashK(height));
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}
