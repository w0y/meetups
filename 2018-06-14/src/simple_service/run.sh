#!/usr/bin/bash
make
socat -v tcp-l:1234,reuseaddr,fork exec:'./service' 
