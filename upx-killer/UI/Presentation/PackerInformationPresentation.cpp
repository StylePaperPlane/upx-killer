#include "pch.h"
#include "UI/Presentation/PackerInformationPresentation.h"

#include <string>

namespace upx_killer::ui::presentation {
winrt::hstring PackerInformationPresentation::Format(
    core::UpxPackerInformation const& information,
    winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader const& resources) {
  using core::UpxPackingAssessment;
  if (information.assessment == UpxPackingAssessment::NotDetected)
    return resources.GetString(L"PackerUpxNotDetected");

  std::wstring result{resources.GetString(L"PackerLikelyUpx")};
  auto append = [&result](winrt::hstring const& value) {
    result.append(L" \u00b7 ");
    result.append(value.c_str());
  };
  append(resources.GetString(information.assessment == UpxPackingAssessment::LikelyStandard
                                 ? L"PackerStandardCharacteristics"
                                 : L"PackerPossiblyModified"));
  if (information.releaseVersion)
    append(winrt::hstring{L"UPX "} + winrt::to_hstring(*information.releaseVersion));
  if (information.packHeaderVersion) {
    auto version = resources.GetString(L"PackerPackHeaderVersionPrefix");
    append(version + winrt::to_hstring(*information.packHeaderVersion));
  }
  if (!information.releaseVersion && !information.packHeaderVersion)
    append(resources.GetString(L"PackerVersionUnavailable"));
  return winrt::hstring{result};
}
}  // namespace upx_killer::ui::presentation
