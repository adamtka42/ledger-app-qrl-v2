#!/bin/bash -eu

# build fuzzers

pushd fuzzing
cmake -DBOLOS_SDK=../BOLOS_SDK -Bbuild -H.
make -C build
mv ./build/fuzz_tx_parser "${OUT}"
mv ./build/fuzz_tx_format "${OUT}"
mv ./build/fuzz_typed_data "${OUT}"
cp ./fuzz_typed_data.options ./fuzz_typed_data.dict "${OUT}"
python3 ./generate_typed_data_corpus.py --zip "${OUT}/fuzz_typed_data_seed_corpus.zip"
popd
