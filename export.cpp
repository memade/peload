#include "stdafx.h"
#include "export.h"

#if !(ENABLE_STATIC_COMPILATION)
__shared_api_ void* __stdcall api_object_init(const void*, unsigned long) {
 void* result = nullptr;
 do {
  local::__gpLibuv = new local::Libuv();
  if (!local::__gpLibuv)
   break;
  result = local::__gpLibuv;
 } while (0);
 return result;
}

__shared_api_ void __stdcall api_object_uninit() {
 SK_DELETE_PTR(local::__gpLibuv);
}
#endif///#if !(ENABLE_STATIC_COMPILATION)
