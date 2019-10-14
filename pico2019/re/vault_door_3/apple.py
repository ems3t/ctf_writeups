flag = 'jU5t_a_sna_3lpm16g84c_u_4_m0r846'
buf = []
for i in range(32):
	buf.append('a')
for i in range(8):
	buf[i] = flag[i]
for i in range(8, 16):
	buf[i] = flag[23-i]
for i in range(16, 32, 2):
	buf[i] = flag[46-i]
for i in range(31, 16, -2):
	buf[i] = flag[i]
buf = "".join(buf)
print 'picoCTF{'+buf+'}'


