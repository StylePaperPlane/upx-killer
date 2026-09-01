.global _start
.section .text
_start:
  movl $20, %eax
  int $0x80
  movl %eax, %ebx
  movl $19, %ecx
  movl $37, %eax
  int $0x80
  xorl %ebx, %ebx
  movl $1, %eax
  int $0x80
