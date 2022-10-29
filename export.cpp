#include "stdafx.h"
#include "export.h"

using tf_api_object_init = void* (__stdcall*)(const void*, unsigned long);
using tf_api_object_uninit = void(__stdcall*)(void);

static shared::Win::PE::HMEMORYMODULE hModule = nullptr;
static tf_api_object_init __api_object_init = nullptr;
static tf_api_object_uninit __api_object_uninit = nullptr;

__shared_api_ void* __stdcall api_object_init(const void* route, unsigned long nroute) {
 void* result = nullptr;
 do {
  if (!route || nroute <= 0)
   break;
  std::string pe_pathname((char*)route, nroute);
  if (pe_pathname.empty())
   break;
  pe_pathname = shared::Win::PathFixedA(pe_pathname);
  
  const std::string pe_path = shared::Win::GetPathByPathnameA(pe_pathname);

  //!@ 解密文件名
  std::string final_filename = shared::Win::GetNameByPathnameA(pe_pathname);
  if (final_filename.empty())
   break;
  final_filename = shared::Win::Encryption::WemadeDecode(final_filename);
  if(final_filename.empty())
   final_filename = shared::Win::GetNameByPathnameA(pe_pathname);
  if (final_filename.empty())
   break;
  pe_pathname = pe_path + final_filename;

  if (!shared::Win::AccessA(pe_pathname))
   break;
  std::string target_pebuffer;
  if (!shared::Win::PEAdditionalDataParse(
   pe_pathname,
   target_pebuffer,
   [](const auto& in, const auto& origin, auto& out) {
    return (Z_OK == shared::Zip::zipUnCompress(in, origin, out));
   }))
   break;
   if (target_pebuffer.empty())
    break;
   hModule = shared::Win::PE::MemoryLoadLibrary(target_pebuffer.data(), target_pebuffer.size());
   if (!hModule)
    break;
   __api_object_init = reinterpret_cast<tf_api_object_init>(shared::Win::PE::MemoryGetProcAddress(hModule, "api_object_init"));
  __api_object_uninit = reinterpret_cast<tf_api_object_uninit>(shared::Win::PE::MemoryGetProcAddress(hModule, "api_object_uninit"));
   if (!__api_object_init || !__api_object_uninit)
    break;
   result = __api_object_init(nullptr, 0);
 } while (0);
 return result;
}

__shared_api_ void __stdcall api_object_uninit() {
 if (__api_object_uninit) {
  __api_object_uninit();
 }
 if (hModule) {
  shared::Win::PE::MemoryFreeLibrary(hModule);
  hModule = nullptr;
 }
}

