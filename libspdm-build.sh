#!/bin/bash
if [ ! -f libspdm/build/lib/libspdm.a ]; then
    echo "libspdm.a not found!!, building..."
    git clone https://github.com/DMTF/libspdm.git
    cd libspdm
    git checkout -b libspdm_build 1a37d663deb2c6613acd7c6d9e1629066d769d17
    git submodule update --init
    git am ../subprojects/libspdm/0003-spdm-cpp.patch
    mkdir build
    cd build
    cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
    make
    ar -M < ../../subprojects/libspdm/libspdm.mri
    cd ../..
fi
exit 0
