#!/usr/bin/env python


flag = ''
def decode(file):
	a = ''
	with open('./'+file, 'rb') as f:
		f.seek(0x7e3)
		a = ''
		for i in range(0x32):
			if i % 5 == 0:
				b = ""
				for k in range(8):
					data = f.read(1)
					b += str(int.from_bytes(data, 'big') & 1)
				c = int(b[::-1], 2)
				a += chr(c)
			else:
				f.read(1)
		return a

for i in range(5):
	flag += decode('Item0'+str(5-i)+'_cp.bmp')
print (flag)