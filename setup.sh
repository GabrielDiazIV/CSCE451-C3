#!/bin/sh

mkdir ~/ghidra_scripts
python3 -m pip install ghidra_bridge
python3 -m ghidra_bridge.install_server ~/ghidra_scripts
cp -r * ~/ghidra_scripts
