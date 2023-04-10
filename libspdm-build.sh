#!/bin/bash
if [ ! -f libspdm/build/lib/libspdm.a ]; then
    echo "libspdm.a not found!!, building..."
    git clone https://github.com/DMTF/libspdm.git
    cd libspdm
    git checkout -b libspdm_build e0f4e94139f20ccbad5a57c2022878f166d2d5e1
    git submodule update --init
    mkdir build
    cd build
    cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
    make
    ar -M < ../../subprojects/libspdm/libspdm.mri
    cd ../..
fi
exit 0
