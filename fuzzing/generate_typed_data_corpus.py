"""Build libFuzzer seeds from the existing go-qrl typed-data vectors."""
import argparse
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Corpus directory, or archive path with --zip")
    parser.add_argument("--zip", action="store_true", help="Write a ClusterFuzzLite seed archive")
    args = parser.parse_args()
    vectors = Path(__file__).resolve().parent.parent / "unit-tests/fixtures/typed_data.txt"
    seeds = {}
    for line in vectors.read_text(encoding="ascii").splitlines():
        name, _digest, payload_hex = line.split()
        payload = bytes.fromhex(payload_hex)
        for control in (0, 1, 63, 254):
            seeds[f"{name}_{control:02x}"] = bytes([control]) + payload
    if args.zip:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(args.output, "w", compression=ZIP_DEFLATED) as archive:
            for name, seed in seeds.items():
                archive.writestr(name, seed)
    else:
        args.output.mkdir(parents=True, exist_ok=True)
        for name, seed in seeds.items():
            (args.output / name).write_bytes(seed)


if __name__ == "__main__":
    main()
