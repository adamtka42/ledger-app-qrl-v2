FROM ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:670f123c1b656bd878c5ef5fa12943fd3156fe054b0b62b3ae2dd3b01a78af58 AS LITE_BUILDER

# Base image with clang toolchain
FROM gcr.io/oss-fuzz-base/base-builder@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760

RUN apt-get update && apt-get install --no-install-recommends -y libssl-dev

# Copy the project's source code.
COPY . $SRC/app-boilerplate
COPY --from=LITE_BUILDER /opt/ledger-secure-sdk $SRC/app-boilerplate/BOLOS_SDK

# Working directory for build.sh
WORKDIR $SRC/app-boilerplate

# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
