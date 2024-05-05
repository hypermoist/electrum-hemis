#!/usr/bin/env bash
export HOME=~
set -eux pipefail
mkdir -p ~/.hemis
cat > ~/.hemis/hemis.conf <<EOF
regtest=1
txindex=1
printtoconsole=1
rpcuser=doggman
rpcpassword=donkey
rpcallowip=127.0.0.1
zmqpubrawblock=tcp://127.0.0.1:21441
zmqpubrawtx=tcp://127.0.0.1:21441
fallbackfee=0.0002
[regtest]
rpcbind=0.0.0.0
rpcport=18554
EOF
rm -rf ~/.hemis/regtest
screen -S hemisd -X quit || true
screen -S hemisd -m -d hemisd -regtest
sleep 6
hemis-cli createwallet test_wallet
addr=$(hemis-cli getnewaddress)
hemis-cli generatetoaddress 150 $addr > /dev/null
