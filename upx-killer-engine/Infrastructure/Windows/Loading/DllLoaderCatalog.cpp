#include "Infrastructure/Windows/Loading/DllLoaderCatalog.h"

#include <Windows.h>

#include <algorithm>

namespace upx_killer::engine::loading {
DllLoaderCatalog::DllLoaderCatalog(std::vector<Registration> registrations)
    : registrations_(std::move(registrations)) {
  std::ranges::sort(registrations_, {}, &Registration::first);
  auto const duplicate = std::ranges::adjacent_find(
      registrations_, [](Registration const& left, Registration const& right) {
        return left.first == right.first;
      });
  if (duplicate != registrations_.end()) registrations_.clear();
}

std::optional<std::filesystem::path> DllLoaderCatalog::Resolve(
    pe::PeFormat format, std::uint32_t& nativeError) const noexcept {
  nativeError = ERROR_SUCCESS;
  auto const found = std::ranges::lower_bound(
      registrations_, format, {}, &Registration::first);
  if (found == registrations_.end() || found->first != format) {
    nativeError = ERROR_NOT_SUPPORTED;
    return std::nullopt;
  }
  std::error_code error;
  if (!std::filesystem::is_regular_file(found->second, error) || error) {
    nativeError = error ? static_cast<std::uint32_t>(error.value())
                        : ERROR_FILE_NOT_FOUND;
    return std::nullopt;
  }
  return found->second;
}
}
