#!/usr/bin/env python

f = open('./whitepages.txt', "rb")
s = f.read()
f.close()
f = open('ItsReversed', "wb")
f.write(s[::-1])
f.close()