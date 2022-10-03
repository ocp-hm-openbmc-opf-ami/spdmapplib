#!/bin/bash
if [ ! -f libspdm/build/lib/libspdm.a ]; then
    echo "libspdm.a not found!!, building..."
    git clone https://github.com/DMTF/libspdm.git
    cd libspdm
    git checkout -b libspdm_build 1f7c06ff0a892ca3877d833cb93ada649c3ab27e
    git submodule update --init
    git am ../subprojects/libspdm/0001-Fix-build-issue.patch
    git am ../subprojects/libspdm/0003-Rename-cplusplus-keywords.patch
    git am ../subprojects/libspdm/0004-Add-spdm-emu-transport-none-lib.patch
    mkdir build
    cd build
    cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=openssl ..
    make
    ar -M < ../../subprojects/libspdm/libspdm.mri
    cd ../..
fi
exit 0
