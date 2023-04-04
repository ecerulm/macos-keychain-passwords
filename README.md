<!--
SPDX-FileCopyrightText: 2023 Ruben Laguna <ruben.laguna@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
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
