extern int write(int fileDescriptor, void const* bytes, unsigned count);
extern void exit(int status);

static char const message[] = "elf32-pie-dynamic:13\n";
char const* volatile messagePointer = message;

__attribute__((used)) static char const compressionPayload[8192] = {'C'};

__attribute__((noreturn)) void _start(void) {
  write(1, messagePointer, sizeof(message) - 1);
  if (compressionPayload[0] != 'C') write(2, compressionPayload, 1);
  exit(13);
}
