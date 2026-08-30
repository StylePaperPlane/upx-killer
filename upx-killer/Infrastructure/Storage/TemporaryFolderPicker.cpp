#include "pch.h"
#include "Infrastructure/Storage/TemporaryFolderPicker.h"

#include <ShObjIdl.h>

namespace upx_killer::infrastructure {

winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> TemporaryFolderPicker::PickAsync(
    std::uintptr_t ownerWindowHandle) {

  auto dialog = winrt::create_instance<IFileOpenDialog>(CLSID_FileOpenDialog);
  FILEOPENDIALOGOPTIONS options{};
  winrt::check_hresult(dialog->GetOptions(&options));
  winrt::check_hresult(
      dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST));

  auto const owner = reinterpret_cast<HWND>(ownerWindowHandle);
  auto const showResult = dialog->Show(owner);
  if (showResult == HRESULT_FROM_WIN32(ERROR_CANCELLED)) co_return winrt::hstring{};
  winrt::check_hresult(showResult);

  winrt::com_ptr<IShellItem> selected;
  winrt::check_hresult(dialog->GetResult(selected.put()));
  PWSTR pathRaw{};
  winrt::check_hresult(selected->GetDisplayName(SIGDN_FILESYSPATH, &pathRaw));
  winrt::hstring const path{pathRaw};
  CoTaskMemFree(pathRaw);
  co_return path;

}

}
