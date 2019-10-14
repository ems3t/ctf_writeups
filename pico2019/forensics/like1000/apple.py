#!/usr/bin/env

import tarfile

for i in range(1000, 0, -1):
	tar = tarfile.open(str(i)+".tar")
	tar.extractall()
	tar.close()