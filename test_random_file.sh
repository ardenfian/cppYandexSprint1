#!/usr/bin/bash

let test_file_size=1024*1024

dd if=/dev/random of=cryptotest.bin bs=$test_file_size count=1 status=none

./build/CryptoGuard --command encrypt --input cryptotest.bin --output file_encrypted.bin --password 111
printf "\n"

./build/CryptoGuard --command decrypt --input file_encrypted.bin --output file_decrypted.bin --password 111
printf "\n"

./build/CryptoGuard --command checksum --input cryptotest.bin

./build/CryptoGuard --command checksum --input file_decrypted.bin

rm cryptotest.bin