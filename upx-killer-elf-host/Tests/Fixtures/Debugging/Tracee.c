#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static void* ExitThread(void* ignored) {
  (void)ignored;
  return NULL;
}

static int RunSharedExecutableMapping(void) {
  static unsigned char const code[] = {
      0xb8, 0x49, 0x00, 0x00, 0x00, /* mov $73, %eax */
      0xc3,                         /* ret */
  };
  int const descriptor =
      (int)syscall(SYS_memfd_create, "upx-killer-hardware-breakpoint", 0);
  if (descriptor < 0) return 70;
  if (write(descriptor, code, sizeof(code)) != (ssize_t)sizeof(code)) {
    close(descriptor);
    return 71;
  }
  void* const mapping = mmap(NULL, sizeof(code), PROT_READ | PROT_EXEC,
                             MAP_SHARED, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) return 72;
  raise(SIGSTOP);
  int (*entry)(void) = NULL;
  memcpy(&entry, &mapping, sizeof(entry));
  int const result = entry();
  munmap(mapping, sizeof(code));
  return result == 73 ? 0 : 73;
}

int main(int argc, char** argv) {
  if (argc != 2) return 64;
  if (strcmp(argv[1], "context") == 0) {
    raise(SIGSTOP);
    return 0;
  }
  if (strcmp(argv[1], "timeout") == 0) {
    for (;;) pause();
  }
  if (strcmp(argv[1], "crash") == 0) {
    raise(SIGSEGV);
    return 65;
  }
  if (strcmp(argv[1], "signal") == 0) {
    raise(SIGUSR1);
    return 66;
  }
  if (strcmp(argv[1], "illegal") == 0) {
    raise(SIGILL);
    return 74;
  }
  if (strcmp(argv[1], "multithread") == 0) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, ExitThread, NULL) != 0) return 67;
    if (pthread_join(thread, NULL) != 0) return 68;
    return 0;
  }
  if (strcmp(argv[1], "hardware-breakpoint") == 0)
    return RunSharedExecutableMapping();
  return 69;
}
