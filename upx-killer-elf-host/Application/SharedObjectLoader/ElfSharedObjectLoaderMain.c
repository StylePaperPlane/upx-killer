#define RTLD_LOCAL 0
#define RTLD_NOW 2
#define SIGSTOP_VALUE 19

extern void* dlopen(char const* file, int mode);
extern int dlclose(void* image);
extern int raise(int signalNumber);

enum {
  InvalidArguments = 64,
  LoadFailed = 65,
  ControlStopFailed = 66,
  UnloadFailed = 67,
};

int RunElfSharedObjectLoader(int argc, char** argv) {
  if (argc != 2) return InvalidArguments;
  void* const image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (image == 0) return LoadFailed;
  if (raise(SIGSTOP_VALUE) != 0) return ControlStopFailed;
  return dlclose(image) == 0 ? 0 : UnloadFailed;
}

#ifndef UPX_KILLER_CUSTOM_ENTRY
int main(int argc, char** argv) {
  return RunElfSharedObjectLoader(argc, argv);
}
#endif
