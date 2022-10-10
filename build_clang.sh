#!/bin/sh

mkdir -p build
pushd build
export CC=$(which clang)
export CXX=$(which clang++)
cmake ../ -D_CMAKE_TOOLCHAIN_PREFIX=llvm- $@
popd
