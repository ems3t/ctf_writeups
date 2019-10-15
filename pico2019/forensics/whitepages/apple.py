#!/usr/bin/env python

from pwn import *

with open('./whitepages.txt', 'r') as f:
	file = f.read()

file = file.replace('\xe2\x80\x83', '0')
file = file.replace('\x20', '1')

print unbits(file)