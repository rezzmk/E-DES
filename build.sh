#!/bin/bash

make cleanall; make
cp speed ../binaries/C/speed
cp encrypt ../binaries/C/encrypt
cp decrypt ../binaries/C/decrypt
