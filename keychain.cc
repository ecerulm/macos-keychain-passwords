// hello.cc
#include <Security/Security.h>
#include <node_api.h>

namespace osxkeychainservices {

napi_value set_password(napi_env env, napi_callback_info args) {
  // get the arguments from napi_callback_info
  size_t argc = 3;
  napi_value argv[3];
  napi_get_cb_info(env, args, &argc, argv, nullptr, nullptr);

  // get the first rgument as a string
  size_t str_len;
  napi_get_value_string_utf8(env, argv[0], NULL, 0, &str_len);
  char *service = new char[str_len + 1];
  napi_get_value_string_utf8(env, argv[0], service, str_len + 1, &str_len);
  CFStringRef cfstrService =
      CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
  delete[] service;

  // get the second argument as a CFStringRef
  napi_get_value_string_utf8(env, argv[1], NULL, 0, &str_len);
  char *account = new char[str_len + 1];
  napi_get_value_string_utf8(env, argv[1], account, str_len + 1, &str_len);
  CFStringRef cfstrAccount =
      CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
  delete[] account;

  // get the second argument as a CFStringRef
  napi_get_value_string_utf8(env, argv[2], NULL, 0, &str_len);
  char *password = new char[str_len + 1];
  napi_get_value_string_utf8(env, argv[2], password, str_len + 1, &str_len);
  CFStringRef cfstrPassword =
      CFStringCreateWithCString(NULL, password, kCFStringEncodingUTF8);
  delete[] password;

  CFStringRef keys[] = {kSecClass, kSecAttrAccount, kSecValueData,
                        kSecAttrService};
  CFTypeRef values[] = {kSecClassGenericPassword, cfstrAccount, cfstrPassword,
                        cfstrService};

  CFDictionaryRef query = CFDictionaryCreate(
      NULL, (const void **)keys, values, sizeof(keys) / sizeof(keys[0]),
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  OSStatus err = SecItemAdd(query, NULL);

  // free cfstrPassword
  CFRelease(cfstrPassword);
  CFRelease(cfstrAccount);
  CFRelease(cfstrService);
  CFRelease(query);

  if (err != errSecSuccess) {
    napi_throw_error(env, "ERR", "Error adding item to keychain");
  }

  return nullptr;
}

// implement a node-api function that get a password using SecItemCopyMatching
napi_value get_password(napi_env env, napi_callback_info args) {
  // get the arguments from napi_callback_info
  size_t argc = 2;
  napi_value argv[2];
  napi_get_cb_info(env, args, &argc, argv, nullptr, nullptr);

  // get the first rgument as a string
  size_t str_len;
  napi_get_value_string_utf8(env, argv[0], NULL, 0, &str_len);
  char *service = new char[str_len + 1];
  napi_get_value_string_utf8(env, argv[0], service, str_len + 1, &str_len);
  CFStringRef cfstrService =
      CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
  delete[] service;

  // get the second argument as a CFStringRef
  napi_get_value_string_utf8(env, argv[1], NULL, 0, &str_len);
  char *account = new char[str_len + 1];
  napi_get_value_string_utf8(env, argv[1], account, str_len + 1, &str_len);
  CFStringRef cfstrAccount =
      CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
  delete[] account;

  CFStringRef keys[] = {kSecClass, kSecAttrAccount, kSecReturnData,
                        kSecAttrService};
  CFTypeRef values[] = {kSecClassGenericPassword, cfstrAccount, kCFBooleanTrue,
                        cfstrService};

  CFDictionaryRef query = CFDictionaryCreate(
      NULL, (const void **)keys, values, sizeof(keys) / sizeof(keys[0]),
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDataRef result = NULL;
  OSStatus err = SecItemCopyMatching(query, (CFTypeRef *)&result);

  // free cfstrPassword
  CFRelease(cfstrAccount);
  CFRelease(cfstrService);
  CFRelease(query);
  if (err != errSecSuccess) {
    napi_throw_error(env, "ERR", "Error adding item to keychain");
  }

  CFStringRef cfstrPassword = CFStringCreateFromExternalRepresentation(
      NULL, result, kCFStringEncodingUTF8);
  CFRelease(result);

  napi_value password;
  napi_create_string_utf8(
      env, CFStringGetCStringPtr(cfstrPassword, kCFStringEncodingUTF8),
      NAPI_AUTO_LENGTH, &password);
  CFRelease(cfstrPassword);

  return password;
}

napi_value init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  status = napi_create_function(env, nullptr, 0, set_password, nullptr, &fn);
  if (status != napi_ok)
    return nullptr;

  status = napi_set_named_property(env, exports, "set_password", fn);
  if (status != napi_ok)
    return nullptr;

  status = napi_create_function(env, nullptr, 0, get_password, nullptr, &fn);
  if (status != napi_ok)
    return nullptr;

  status = napi_set_named_property(env, exports, "get_password", fn);
  if (status != napi_ok)
    return nullptr;

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

} // namespace osxkeychainservices
