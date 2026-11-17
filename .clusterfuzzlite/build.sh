#!/bin/bash -eu
set -eu

# build fuzzers

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build
mv ./build/fuzz_tx_parser "${OUT}"
mv ./build/fuzz_tx_format "${OUT}"
mv ./build/fuzz_contract_call "${OUT}"
cp fuzz_contract_call.options "${OUT}"
python3 generate_contract_corpus.py "${OUT}/fuzz_contract_call_seed_corpus.zip"
mv ./build/fuzz_staking_deposit "${OUT}"
cp fuzz_staking_deposit.options "${OUT}"
python3 -c 'import zipfile; from pathlib import Path; data=Path("../unit-tests/fixtures/staking_deposit.bin").read_bytes(); value=(40000*10**18).to_bytes(32,"big"); z=zipfile.ZipFile("'"${OUT}"'/fuzz_staking_deposit_seed_corpus.zip","w"); z.writestr("known_root", value+data); z.close()'
popd
