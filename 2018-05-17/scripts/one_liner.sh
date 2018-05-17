#!/bin/bash

# TODO add reference
objdump 4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652 -d -M intel| grep 'cmp *rdi' | python3 -c 'while 1: print(chr(int(input()[-2:],16)),end="")' 2>/dev/null
