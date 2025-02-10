#!/bin/bash

if [ -z "$1" ]; then
        interval=8
else
        interval=$1
fi

pid=`docker ps | grep blockstream/esplora | awk '{print $1}'`
echo "Targeting container $pid ..."

# echo "Loading default wallet ..."
# load_wallet_command="/srv/explorer/bitcoin/bin/bitcoin-cli -conf=/data/.bitcoin.conf -datadir=/data/bitcoin loadwallet default"
# docker exec $pid /bin/bash -c "$load_wallet_command"

set -e

echo "Generating a block every $interval seconds. Press [CTRL+C] to stop.."

address_command="/srv/explorer/bitcoin/bin/bitcoin-cli -conf=/data/.bitcoin.conf -datadir=/data/bitcoin getnewaddress"
address=`docker exec $pid /bin/bash -c "$address_command"`

generate_command="/srv/explorer/bitcoin/bin/bitcoin-cli -conf=/data/.bitcoin.conf -datadir=/data/bitcoin generatetoaddress 1 $address"

while :
do
        echo "Generating a new block `date '+%d/%m/%Y %H:%M:%S'` ..."
        docker exec $pid /bin/bash -c "$generate_command"
        sleep $interval
done