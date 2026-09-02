.text
.global _start
.type _start, @function
.extern RunElfSharedObjectLoader
_start:
  mov (%esp), %eax
  lea 4(%esp), %edx
  push %edx
  push %eax
  call RunElfSharedObjectLoader
  add $8, %esp
  mov %eax, %ebx
  mov $1, %eax
  int $0x80
.size _start, .-_start
