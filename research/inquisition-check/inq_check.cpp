// ADR-018: cross-check the ADR-015/016/017 vectors against Bitcoin Inquisition's own interpreter.
//
// It is linked against Inquisition's bitcoin_consensus library (tag v29.4-inq) and calls
// VerifyScript with the Taproot consensus flags. Mode "cat" adds SCRIPT_VERIFY_OP_CAT, which is
// Inquisition's BIP347 deployment flag; mode "nocat" leaves it out, so 0x7e stays OP_SUCCESS126.
// Expected results:
// - cat must reproduce `bip347_valid` (the local patch);
// - nocat must reproduce `core_valid` (stock Core 26).
// Input comes from to-lines.mjs, one case per line:
//   name expected design tx_hex input_index n_spent (spk_hex value)*
// This checks Script only: not UTXO existence, chain, relay policy or mining.
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <streams.h>
#include <util/strencodings.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    if (argc != 2 || (std::string(argv[1]) != "cat" && std::string(argv[1]) != "nocat")) {
        std::cerr << "usage: inq_check cat|nocat < lines\n";
        return 2;
    }
    const bool cat = std::string(argv[1]) == "cat";
    script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_NULLDUMMY |
                                SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT;
    if (cat) flags |= SCRIPT_VERIFY_OP_CAT;

    std::string line;
    int cases = 0, mismatches = 0, counterexamples = 0;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string name, expect_s, design_s, tx_hex;
        unsigned int idx = 0, n_spent = 0;
        ss >> name >> expect_s >> design_s >> tx_hex >> idx >> n_spent;
        std::vector<CTxOut> spent;
        for (unsigned int i = 0; i < n_spent; ++i) {
            std::string spk_hex;
            long long value = 0;
            ss >> spk_hex >> value;
            const auto spk = ParseHex(spk_hex);
            spent.emplace_back(CAmount{value}, CScript(spk.begin(), spk.end()));
        }
        const auto raw = ParseHex(tx_hex);
        DataStream ds{raw};
        CMutableTransaction mtx;
        ds >> TX_WITH_WITNESS(mtx);
        const CTransaction tx(mtx);
        if (spent.size() != tx.vin.size() || idx >= tx.vin.size()) {
            std::cerr << name << ": spent outputs do not match inputs\n";
            return 2;
        }
        PrecomputedTransactionData txdata;
        txdata.Init(tx, std::vector<CTxOut>(spent), /*force=*/true);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(tx.vin[idx].scriptSig, spent[idx].scriptPubKey, &tx.vin[idx].scriptWitness, flags,
                                     TransactionSignatureChecker(&tx, idx, spent[idx].nValue, txdata, MissingDataBehavior::FAIL),
                                     &err);
        const bool expect = expect_s == "true";
        const bool design = design_s == "true";
        ++cases;
        if (ok != expect) ++mismatches;
        if (ok && !design) ++counterexamples;
        std::cout << (ok == expect ? "ok    " : "FAIL  ") << name << " inquisition=" << (ok ? "valid" : "invalid")
                  << " expected=" << expect_s << " " << ScriptErrorString(err) << "\n";
    }
    std::cout << "Bitcoin Inquisition v29.4-inq (" << (cat ? "SCRIPT_VERIFY_OP_CAT" : "no OP_CAT flag") << "): "
              << cases << " cases, mismatches: " << mismatches << ", consensus-valid counterexamples: " << counterexamples << "\n";
    return mismatches == 0 ? 0 : 1;
}
