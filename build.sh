#!/bin/bash

echo "Building everything..."
echo ""
echo "make output:"
echo "---------------------------------------------"

make cleanall; make
echo "---------------------------------------------"

echo ""
echo "moving binaries to ../binaries/C/"
mv speed ../binaries/C/speed
mv encrypt ../binaries/C/encrypt
mv decrypt ../binaries/C/decrypt



