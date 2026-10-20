#!/usr/bin/env bash
# Starts a throwaway Bitcoin Core regtest node for the harness, in the foreground.
#   scripts/regtest-node.sh <datadir> [path/to/bitcoind] [extra bitcoind args...]
# The RPC credentials are fixed test values; RPC is bound to 127.0.0.1 and the node makes no P2P connections.
# On Windows a wallet path over 260 characters fails in SQLite ("Unable to obtain an exclusive lock"), so
# with a deep datadir pass a short -walletdir=<existing dir> (the on-chain payment run uses wallets).
set -euo pipefail
dir="$1"
bitcoind="${2:-bitcoind}"
mkdir -p "$dir"
cat > "$dir/bitcoin.conf" <<CONF
regtest=1
server=1
txindex=1
acceptnonstdtxn=0
[regtest]
rpcuser=bsb
rpcpassword=bsb-regtest-only
rpcport=18543
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
port=18544
connect=0
listen=0
CONF
exec "$bitcoind" -datadir="$dir" "${@:3}"
