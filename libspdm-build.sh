#!/bin/bash
if [ ! -f libspdm/build/lib/libspdm.a ]; then
    echo "libspdm.a not found!!, building..."
    git clone https://github.com/DMTF/libspdm.git
    cd libspdm
    git checkout -b libspdm_build 269e520c0bd87c2b82f4455f7c3e9b3f87b8eca5
    git submodule update --init
    mkdir build
    cd build
    cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
    make
    ar -M < ../../subprojects/libspdm/libspdm.mri
    cd ../..
fi
exit 0
