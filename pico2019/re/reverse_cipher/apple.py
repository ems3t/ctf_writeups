#!/usr/bin/env python

flag = 'picoCTF{w1{1wq84>654f26}'
new_flag = ''
for i in range(8):
	new_flag+= flag[i]
for i in range(8, 23):
	if i % 2 == 0:
		new_flag+= chr(ord(flag[i])-0x5)
	else:
		new_flag+= chr(ord(flag[i])+2)
print new_flag+'}'