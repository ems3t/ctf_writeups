asm1:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	cmp    DWORD PTR [ebp+0x8],0x37a	#compare 0x37a to var1(0x345)
	<+10>:	jg     0x512 <asm1+37>				# 0x37a is GREATER than var1, we jump to asm37
	<+12>:	cmp    DWORD PTR [ebp+0x8],0x345	
	<+19>:	jne    0x50a <asm1+29>				
	<+21>:	mov    eax,DWORD PTR [ebp+0x8] 		
	<+32>:	sub    eax,0x3 						
	<+24>:	add    eax,0x3 						
	<+27>:	jmp    0x529 <asm1+60> 				
	<+29>:	mov    eax,DWORD PTR [ebp+0x8]		
	<+35>:	jmp    0x529 <asm1+60>
	<+37>:	cmp    DWORD PTR [ebp+0x8],0x5ff 	#compare 0x5ff to var1(0x345)
	<+44>:	jne    0x523 <asm1+54>				#0x5ff is NOT equal to var1, we jump to asm1 54
	<+46>:	mov    eax,DWORD PTR [ebp+0x8]
	<+49>:	sub    eax,0x3
	<+52>:	jmp    0x529 <asm1+60>
	<+54>:	mov    eax,DWORD PTR [ebp+0x8]		#load var into eax
	<+57>:	add    eax,0x3 						#0x345+0x3 = 0x348
	<+60>:	pop    ebp 							#flag pop
	<+61>:	ret    

#	0x4 	0x8 	0xc
#	return 	var1	var2