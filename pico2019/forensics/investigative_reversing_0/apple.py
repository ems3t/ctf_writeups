#!/usr/bin/env python

og = 'picoCTK.k5zsid6q_5266a857}'

flag = 'picoCT'

second = 'K.k5zsid6q'

third = og[16:26]
for i in second:
	flag+= chr(ord(i)-0x5)

flag+= third

print flag

