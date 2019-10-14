
void main(void)

{
  FILE *flag_input;
  FILE *pic1;
  FILE *pic2;
  FILE *pic3;
  long in_FS_OFFSET;
  char local_6b;
  int i;
  int local_64;
  int local_60;
  char flag [4];
  char local_34;
  char local_33;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  flag_input = fopen("flag.txt","r");
  pic1 = fopen("mystery.png","a");
  pic2 = fopen("mystery2.png","a");
  pic3 = fopen("mystery3.png","a");
  if (flag_input == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (pic1 == (FILE *)0x0) {
    puts("mystery.png is missing, please run this on the server");
  }
  fread(flag,0x1a,1,flag_input); //read flag into flag
  fputc((int)flag[1],pic3); // 2nd char into pic3: i  flag  so far : _i________________________
  fputc((int)(char)(flag[0] + '\x15'),pic2);
  fputc((int)flag[2],pic3);
  local_6b = flag[3];
  fputc((int)local_33,pic3);
  fputc((int)local_34,pic1);
  i = 6;
  while (i < 10) {
    local_6b = local_6b + '\x01';
    fputc((int)flag[(long)i],pic1);
    i = i + 1;
  }
  fputc((int)local_6b,pic2);
  local_64 = 10;
  while (local_64 < 0xf) {
    fputc((int)flag[(long)local_64],pic3);
    local_64 = local_64 + 1;
  }
  local_60 = 0xf;
  while (local_60 < 0x1a) {
    fputc((int)flag[(long)local_60],pic1);
    local_60 = local_60 + 1;
  }
  fclose(pic1);
  fclose(flag_input);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

