#!/usr/bin/env python2

# Side-channel attack exploiting the exit value
from pwn import *
import string

context.log_level = "error"
def try_input(inp):
    with process('./4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652') as p: 
        p.recvuntil(':')
        p.sendline(inp)
        return p.poll(block=True)

correct_input = ""
return_code = 1
while return_code != 0:
    for c in string.printable:
        return_code = try_input(correct_input + c)
        if return_code != len(correct_input) + 1:
            correct_input += c
            print(correct_input)
            break

print("this is you valid input: '{0}'".format(correct_input))
