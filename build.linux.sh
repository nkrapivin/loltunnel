#!/bin/sh
# LOLTunnel-NG Linux build script
# (C) nkrapivindev.ru
clang++ hansock_lin.c loltunnelng.cpp -std=c++17 -Wno-switch -fPIC -fpie -O3 -o loltunnelng.release
clang++ hansock_lin.c loltunnelng.cpp -std=c++17 -Wno-switch -fPIC -fpie -O0 -g -o loltunnelng.debug
