#!/bin/bash -eu

# build fuzzers

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build
mv ./build/fuzz_tx_parser "${OUT}"
mv ./build/fuzz_tx_format "${OUT}"
mv ./build/fuzz_contract_call "${OUT}"
cp fuzz_contract_call.options "${OUT}"
python3 generate_contract_corpus.py "${OUT}/fuzz_contract_call_seed_corpus.zip"
popd
