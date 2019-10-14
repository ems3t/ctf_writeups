
undefined8 main(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  char local_7e;
  char local_7d;
  int local_7c;
  int local_78;
  int local_74;
  uint local_70;
  undefined4 local_6c;
  int local_68;
  int local_64;
  FILE *flag_input;
  FILE *og_bmp;
  FILE *enc_bmp;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_6c = 0;
  flag_input = fopen("flag.txt","r");
  og_bmp = fopen("original.bmp","r");
  enc_bmp = fopen("encoded.bmp","a");
  if (flag_input == (FILE *)0x0) {
    puts("No flag found, please make sure this is run on the server");
  }
  if (og_bmp == (FILE *)0x0) {
    puts("original.bmp is missing, please run this on the server");
  }
  sVar1 = fread(&local_7e,1,1,og_bmp);
  local_7c = (int)sVar1;
  local_68 = 2000;
  local_78 = 0;
  while (local_78 < local_68) {
    fputc((int)local_7e,enc_bmp);
    sVar1 = fread(&local_7e,1,1,og_bmp);
    local_7c = (int)sVar1;
    local_78 = local_78 + 1;
  }
  sVar1 = fread(local_48,0x32,1,flag_input);
  local_64 = (int)sVar1;
  if (local_64 < 1) {
    puts("flag is not 50 chars");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  local_74 = 0;
  while (local_74 < 0x32) {
    local_70 = 0;
    while ((int)local_70 < 8) {
      local_7d = codedChar((ulong)local_70,(ulong)(uint)(int)(char)(local_48[(long)local_74] + -5),
                           (ulong)(uint)(int)local_7e,
                           (ulong)(uint)(int)(char)(local_48[(long)local_74] + -5));
      fputc((int)local_7d,enc_bmp);
      fread(&local_7e,1,1,og_bmp);
      local_70 = local_70 + 1;
    }
    local_74 = local_74 + 1;
  }
  while (local_7c == 1) {
    fputc((int)local_7e,enc_bmp);
    sVar1 = fread(&local_7e,1,1,og_bmp);
    local_7c = (int)sVar1;
  }
  fclose(enc_bmp);
  fclose(og_bmp);
  fclose(flag_input);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

