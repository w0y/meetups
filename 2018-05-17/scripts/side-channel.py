#!/usr/bin/env python2

# Side-channel attack exploiting counting instructions
from pwn import *
import string
import sys
from subprocess import Popen, PIPE, STDOUT

executable = sys.argv[1]
key = [' '] * 100
cmd = "perf stat -x, -e instructions:u " + executable + " 1>/dev/null"

for i in range(len(key)):
    maximum = 0
    character = 'x'

    for c in string.printable:
        key[i] = c
        key_str = ''.join(key)

        p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        stdout, _ = p.communicate(input=b'%s\n' % key_str)

        nb_instructions = int(stdout.split(',')[0])
        if nb_instructions > maximum:
            maximum = nb_instructions
            character = c

    key[i] = character
    p = Popen(executable, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
    stdout, _ = p.communicate(input=b'%s \n' % ''.join(key))
    if "sum is" in stdout:
        print("flag is: '" + ''.join(key) + "'")
        break
    print(''.join(key))
