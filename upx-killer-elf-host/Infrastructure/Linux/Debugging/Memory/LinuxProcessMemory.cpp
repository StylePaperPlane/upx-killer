#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.h"

#include <sys/ptrace.h>
#include <sys/uio.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace upx_killer::elf_host::debugging {
std::vector<LinuxMemoryMapping> LinuxProcessMemory::ReadMappings(pid_t pid) {
  std::vector<LinuxMemoryMapping> result;
  std::ifstream stream("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(stream, line)) {
    std::istringstream input(line);
    std::string range, permissions, offset, device, inode;
    if (!(input >> range >> permissions >> offset >> device >> inode)) continue;
    std::string path;
    std::getline(input, path);
    auto const separator = range.find('-');
    if (separator == std::string::npos || permissions.size() < 4) continue;
    LinuxMemoryMapping mapping{};
    mapping.begin = std::stoull(range.substr(0, separator), nullptr, 16);
    mapping.end = std::stoull(range.substr(separator + 1), nullptr, 16);
    mapping.read = permissions[0] == 'r';
    mapping.write = permissions[1] == 'w';
    mapping.execute = permissions[2] == 'x';
    mapping.offset = std::stoull(offset, nullptr, 16);
    auto const nonSpace = path.find_first_not_of(' ');
    if (nonSpace != std::string::npos) mapping.path = path.substr(nonSpace);
    result.push_back(std::move(mapping));
  }
  return result;
}

bool LinuxProcessMemory::Read(pid_t pid, std::uint64_t address,
                              std::span<std::byte> output) noexcept {
  iovec local{output.data(), output.size()};
  iovec remote{reinterpret_cast<void*>(address), output.size()};
  auto const read = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (read == static_cast<ssize_t>(output.size())) return true;
  std::size_t offset{};
  while (offset < output.size()) {
    errno = 0;
    auto const word = ptrace(PTRACE_PEEKDATA, pid,
                             reinterpret_cast<void*>(address + offset), nullptr);
    if (word == -1 && errno != 0) return false;
    auto const count = std::min(sizeof(word), output.size() - offset);
    std::memcpy(output.data() + offset, &word, count);
    offset += count;
  }
  return true;
}
}  // namespace upx_killer::elf_host::debugging
