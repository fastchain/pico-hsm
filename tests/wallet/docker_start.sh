#!/bin/bash -eu

GITROOT=$(git rev-parse --show-toplevel)

docker container run -it --volume $GITROOT:/pico-hsm --workdir /pico-hsm  -v /dev/bus/usb:/dev/bus/usb  --privileged   pico-hsm-test:wallet bash
