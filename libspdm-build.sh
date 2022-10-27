#!/bin/bash
if [ ! -f libspdm/build/lib/libspdm.a ]; then
    echo "libspdm.a not found!!, building..."
    git clone https://github.com/DMTF/libspdm.git
    cd libspdm
    git checkout -b libspdm_build d3f5c697319b5dfeee387eeabb1f644221ff0e7d
    git submodule update --init
    mkdir build
    cd build
    cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
    make
    ar -M < ../../subprojects/libspdm/libspdm.mri
    cd ../..
fi
exit 0
