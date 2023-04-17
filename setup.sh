#!/bin/sh

mkdir -p ~/ghidra_scripts/examples
python3 -m pip install ghidra_bridge
python3 -m ghidra_bridge.install_server ~/ghidra_scripts
cp -r * ~/ghidra_scripts
