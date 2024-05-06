#!/bin/bash

# Check if there is an argument
if [ -z "$1" ]; then
        echo "No LLVM version supplied"
        exit 1
fi

update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-$1 200
update-alternatives --install /usr/bin/clang clang /usr/bin/clang-$1 200

update-alternatives --install \
        /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-$1 200 \
        --slave /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-$1 \
        --slave /usr/bin/llvm-as llvm-as /usr/bin/llvm-as-$1 \
        --slave /usr/bin/llvm-bcanalyzer llvm-bcanalyzer /usr/bin/llvm-bcanalyzer-$1 \
        --slave /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-$1 \
        --slave /usr/bin/llvm-diff llvm-diff /usr/bin/llvm-diff-$1 \
        --slave /usr/bin/llvm-dis llvm-dis /usr/bin/llvm-dis-$1 \
        --slave /usr/bin/llvm-dwarfdump llvm-dwarfdump /usr/bin/llvm-dwarfdump-$1 \
        --slave /usr/bin/llvm-extract llvm-extract /usr/bin/llvm-extract-$1 \
        --slave /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-$1 \
        --slave /usr/bin/llvm-mc llvm-mc /usr/bin/llvm-mc-$1 \
        --slave /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-$1 \
        --slave /usr/bin/llvm-ranlib llvm-ranlib /usr/bin/llvm-ranlib-$1 \
        --slave /usr/bin/llvm-readobj llvm-readobj /usr/bin/llvm-readobj-$1 \
        --slave /usr/bin/llvm-rtdyld llvm-rtdyld /usr/bin/llvm-rtdyld-$1 \
        --slave /usr/bin/llvm-size llvm-size /usr/bin/llvm-size-$1 \
        --slave /usr/bin/llvm-stress llvm-stress /usr/bin/llvm-stress-$1 \
        --slave /usr/bin/llvm-tblgen llvm-tblgen /usr/bin/llvm-tblgen-$1 \
        --slave /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-$1