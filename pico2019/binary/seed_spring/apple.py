#!/usr/bin/env python

from pwn import *

p = process('./seed_spring')

print proc.pidof(p)

p.interactive()

