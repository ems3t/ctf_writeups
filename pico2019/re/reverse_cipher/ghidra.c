
void main(void)

{
  size_t sVar1;
  char flag_var [23];
  char local_41;
  int local_2c;
  FILE *rev_this;
  FILE *flag;
  uint j;
  int i;
  char local_9;
  
  flag = fopen("flag.txt","r");
  rev_this = fopen("rev_this","a");
  if (flag == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (rev_this == (FILE *)0x0) {
    puts("please run this on the server");
  }
  sVar1 = fread(flag_var,0x18,1,flag);
  local_2c = (int)sVar1;
  if (local_2c < 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  i = 0;
  while (i < 8) {
    local_9 = flag_var[(long)i];
    fputc((int)local_9,rev_this);
    i = i + 1;
  }
  j = 8;
  while ((int)j < 0x17) {
    if ((j & 1) == 0) {
      local_9 = flag_var[(long)(int)j] + '\x05';
    }
    else {
      local_9 = flag_var[(long)(int)j] + -2;
    }
    fputc((int)local_9,rev_this);
    j = j + 1;
  }
  local_9 = local_41;
  fputc((int)local_41,rev_this);
  fclose(rev_this);
  fclose(flag);
  return;
}

