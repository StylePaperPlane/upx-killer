.global _start

.section .text
_start:
  call 1f
1:
  popl %ecx
  addl $(message - 1b), %ecx
  movl $4, %eax
  movl $1, %ebx
  movl $message_length, %edx
  int $0x80

  movl $1, %eax
  movl $7, %ebx
  int $0x80

.section .rodata
message:
  .ascii "elf32-plan:7\n"
.set message_length, . - message
fixture_payload:
  .fill 8192, 1, 0x41
