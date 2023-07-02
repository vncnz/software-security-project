#include <stdio.h>
#include <string.h>

// Mi serve avere pop rdi nel sorgente ma nei programmi molto piccoli può mancare...
void callme() {
  asm volatile ("pop %%rdi\n\t"
      "ret"
      :
      :
      : "rdi");
}

int main(int argc, const char **argv)
{
  char s[16];
 
  printf("Enter name : ");
  fgets(s, 16, stdin);
  puts("Hello");
  printf(s, 16);
  printf("Enter sentence : ");
  fgets(s, 256, stdin);
  return 0;
}