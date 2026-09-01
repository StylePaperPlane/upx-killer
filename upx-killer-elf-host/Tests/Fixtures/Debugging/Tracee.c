#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static void* ExitThread(void* ignored) {
  (void)ignored;
  return NULL;
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
  if (strcmp(argv[1], "multithread") == 0) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, ExitThread, NULL) != 0) return 67;
    if (pthread_join(thread, NULL) != 0) return 68;
    return 0;
  }
  return 69;
}
