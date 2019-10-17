#!/usr/bin/env python

from pwn import *
import sys
import ctypes

argv = sys.argv
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
LIBC.srand(LIBC.time(0))

if len(argv) > 1:
	p = remote('2019shell1.picoctf.com', 45107)
else:
	p = process('./seed_spring')

for i in range(100):
	try: 
		LIBC.srand(LIBC.time(0)-i)

		for j in range(30):
			p.sendlineafter('height:', str(LIBC.rand() & 0xf))
	except:
		pass

p.interactive()

