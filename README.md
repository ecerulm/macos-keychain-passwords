<!--
SPDX-FileCopyrightText: 2023 Ruben Laguna <ruben.laguna@gmail.com>

SPDX-License-Identifier: MIT
-->

# Description

Allows access to macOS Keychain via the the native OS X Security Framework API ([SecItemAdd](https://developer.apple.com/documentation/security/1401659-secitemadd), [SecItemCopyMatching](https://developer.apple.com/documentation/security/1401659-secitemadd))

# Usage

Install with

```
npm install macos-keychain-passwords
```

Then use it:

```
var keychain = require("macos-keychain-passwords");
keychain.set_password("myservice_or_app", "myusername", "mypassword")
keychain.get_password("myservice_or_app", "myusername") // returns "mypassword"
```

# TODO

- Add `delete_password`
- Add posibility of internet password (`kSecClassInternetPassword`) in addition to generic password (`kSecClassGenericPassword`)
- Add callback API
- Add Promise API

# Instructions to npm publish

```
npm version patch # Bump the version
npm run prebuild # runs prebuildify to generate the prebuilds/xxxx
git push
npm publish
```

# Links

- [macos-keychain-passwords in npmjs.org](https://www.npmjs.com/package/macos-keychain-passwords)
