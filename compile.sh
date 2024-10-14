#!/bin/bash
mkdir -p program
cd src
mkdir -p build
cd build
cmake ..
make
cp main ../../program

# CodeBy FarnoodID