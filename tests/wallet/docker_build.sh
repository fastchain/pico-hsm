#!/bin/bash -eu

# Figure out the number of processors available
if [ "$(uname)" == "Darwin" ]; then
    NUM_PROC="$(sysctl -n hw.logicalcpu)"
else
    NUM_PROC="$(nproc)"
fi

docker image build --no-cache \
        -t "pico-hsm-test:wallet" \
        --cache-from="pico-hsm-test:wallet" \
        --network host \
        --build-arg MAKEFLAGS_PARALLEL="-j ${NUM_PROC}" \
        .