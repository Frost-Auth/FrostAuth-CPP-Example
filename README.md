# FrostAuth-CPP-Example 🌟

C++ example for the FrostAuth licensing API at https://www.frostauth.cc.

Copy `frostauth.hpp` and `frostauth.cpp` into your project and link libsodium. The example ships as source.

## Bugs

If the example fails with little or no modification, open an issue with your FrostAuth version, compiler version, and the exact error. SDK support covers bugs you can reproduce with the example.

## Security practices

- If you use VMProtect or Themida, put the protector's markers around the license checks.
- Run integrity checks during the session. End the session if a check detects tampering.
- Keep files you need to protect on the server. Clear temporary buffers when the app is done with them.
- Use the API to recheck licenses and enforce access to server resources there. A local `isValid` flag alone can't enforce access.

The SDK verifies signed responses with the bundled key. Integrity checks make client-side tampering harder, and device rules limit where a key can be used.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing service for software. It offers hardware-locked licenses, app authentication, real-time analytics, and a dashboard for operators. SDKs are available for [C++](https://www.frostauth.cc), C#, Python, Go, Rust, Java, and JavaScript. Product questions go to https://www.frostauth.cc/discord.

## Requirements

- CMake 3.20 or newer, Ninja, and a C++17 compiler.
- Install libsodium with `vcpkg install libsodium:x64-mingw-static` on Windows, `apt install libsodium-dev` on Linux, or `brew install libsodium` on macOS.
- Windows uses WinHTTP. Linux and macOS require libcurl.

## Build

```bash
cd FrostAuth-CPP-Example
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/frostauth-console.exe
```

CMake looks for vcpkg under `C:/vcpkg` or `%VCPKG_ROOT%`. You can also pass the toolchain path directly.

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-mingw-static
cmake --build build
```

## `FrostAuthClient` instance definition

In the FrostAuth dashboard, open the product and copy its owner ID and product ID into [`examples/console_main.cpp`](examples/console_main.cpp). Set the version to the one your app ships.

```cpp
frostauth::Options o;
o.owner = "0809y7MP";                                  // dashboard → product → owner id
o.product = "33abf48a-8e33-4df5-a4bd-d79195704d52";    // dashboard → product → product id
o.version = "1.0.0";                                   // must match the version you ship
```

## Initialize application

Call `Init()` before making other SDK calls. It fetches the public product catalog and compares the server's key ID and Ed25519 public key with the values bundled in the SDK. Initialization fails if they differ. The SDK uses the pinned key to verify signed responses.

```cpp
try {
    app->Init();
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Init failed: " << e.what() << "\n";
    return 1;
}
```

## Display application information

Call `AppData()` after activation or sign-in returns a session token.

```cpp
frostauth::Json appData = app->AppData();
const frostauth::Json* prod = appData.find("product");
std::cout << "App Version: " << (prod ? prod->str_or("version") : "?") << "\n";
std::cout << "Customer panel: " << (prod ? "enabled" : "unknown") << "\n";
std::cout << "Keys: " << appData.str_or("numKeys") << "\n";
std::cout << "Users: " << appData.str_or("numUsers") << "\n";
```

## Check session validation

Use `Validate()` after activation or sign-in to check the license again. If the API rejects a stale session token, the SDK retries once with the stored license key when it has one.

```cpp
try {
    frostauth::Json snap = app->Validate();
    std::cout << "Session OK\n";
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Session invalid: " << e.what() << "\n";
    return 1;
}
```

## Check blacklist status

`CheckBlacklist()` requires an active session. The API checks blacklist rules during login and registration as well.

```cpp
try {
    app->CheckBlacklist();
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Blocked: " << e.what() << "\n";
    return 1;
}
```

## Login with username/password

```cpp
std::string username = Ask("Username: ");
std::string password = Ask("Password: ");
try {
    frostauth::Json snap = app->Login(username, password);
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Login failed: " << e.what() << "\n";
    return 1;
}
```

## Register with username/password/key

```cpp
std::string key = Ask("License: ");
std::string username = Ask("Username: ");
std::string password = Ask("Password: ");
try {
    frostauth::Json snap = app->Register(key, username, password);
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Register failed: " << e.what() << "\n";
    return 1;
}
```

## Upgrade user with key

Apply a license key to an existing account to add time. Sign in after the upgrade to open a session.

```cpp
std::string username = Ask("Username: ");
std::string password = Ask("Password: ");
std::string key = Ask("License: ");
app->Upgrade(username, password, key);
std::cout << "Upgraded. Sign in to use the new licence.\n";
app->Login(username, password);
```

## Login with just license key

For a key-only product, activate with the license key. The API applies the product's device rules and issues a session token where supported.

```cpp
std::string key = Ask("License: ");
try {
    frostauth::Json snap = app->Activate(key);
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Activation failed: " << e.what() << "\n";
    return 1;
}
```

## User Data

Read the current user, account, device, and subscriptions from the snapshot.

```cpp
frostauth::Json snap = app->Snapshot();
std::cout << "Username: " << snap.str_or("user") << "\n";
const frostauth::Json* account = snap.find("account");
const frostauth::Json* device = snap.find("device");
std::cout << "IP: " << (account ? account->str_or("lastIp") : "?") << "\n";
std::cout << "Device Id: " << (device ? device->str_or("id") : "?") << "\n";
if (const frostauth::Json* subs = snap.find("subscriptions"); subs && subs->is_array()) {
    for (size_t i = 0; i < subs->array.size(); ++i) {
        const frostauth::Json& sub = subs->array[i];
        std::cout << "Subscription: " << sub.str_or("tier", sub.str_or("status").c_str()) << "\n";
    }
}
```

## Check subscription of user

Use the tier name you configured in the dashboard. The server matches tier names case-insensitively.

```cpp
bool hasPro = false;
if (const frostauth::Json* subs = app->Snapshot().find("subscriptions");
    subs && subs->is_array()) {
    for (const auto& sub : subs->array) {
        std::string tier = sub.str_or("tier");
        for (auto& c : tier) c = (char)tolower(c);
        if (tier == "pro") { hasPro = true; break; }
    }
}
if (!hasPro) {
    std::cout << "This feature needs a Pro subscription.\n";
    return 1;
}
```

## Application variables

Edit shared strings such as feature flags, configuration, and the message of the day in the dashboard. The SDK reads them subject to the API's tier and version rules.

```cpp
std::string motd = app->Variable("maintenance_message");
std::cout << "MOTD: " << motd << "\n";
```

## User Variables

Use these calls to read and update values for the current user. The API blocks writes to variables the operator marked read-only.

```cpp
frostauth::Json all = app->ListVars();                       // every variable on this user
frostauth::Json theme = app->GetVar("theme");                // one variable: theme.json value
app->SetVar("theme", "dark");                                // write it back
std::cout << "theme: " << theme.str_or("value") << "\n";
```

## Application Logs

Use `Log()` to report events such as crashes or failed integrity checks. The API sends events to the configured Discord webhook if one is set. Dashboard logs rotate after 30 days.

```cpp
app->Log("client started, integrity check passed");
```

## Ban the user

Call `Ban()` after sign-in to blacklist the device's hardware ID and IP address. The SDK ends the local session even if the call fails.

```cpp
app->Ban("debugger detected");
```

The ban reason appears in the dashboard and when the user next tries to sign in.

```cpp
app->Ban("memory patch detected at 0x140001000");
```

## Server-sided webhooks

Call a webhook by the ID the operator configured. The API stores the destination and applies the product's tier rules. The client sends the parameters and body.

```cpp
frostauth::Json res = app->Webhook("discord", "", "{\"content\":\"Hello from FrostAuth\"}");
std::cout << "upstream " << res.str_or("status") << " (ok: " << res.dump() << ")\n";
```

## Download file

> The server currently disables file downloads. `File()` throws `File downloads are disabled on this server`. The example shows how to save a file once downloads are available.

Operators upload files per product. File access follows the product's tier and version rules.

```cpp
try {
    std::vector<unsigned char> bytes = app->File("loader");
    std::ofstream out("loader.bin", std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Download failed: " << e.what() << "\n";
    return 1;
}
```

## Changing username

A signed-in user can change their username after the API checks their password again.

```cpp
std::string name = Ask("New username: ");
frostauth::Json res = app->ChangeUsername(name, Ask("Password: "));
std::cout << "Renamed to " << res.str_or("username") << "\n";
```

## Heartbeat & offline

The heartbeat calls `Validate()` on a timer. If the connection drops, `CheckOffline()` verifies the cached signed assertion locally. A valid assertion allows offline use through its expiry. If the assertion expires or fails verification, the next failed heartbeat clears the active state. The configured grace period applies to sessions that received no assertion.

```cpp
app->StartHeartbeat();   // validates on the server cadence until Stop/Close
// ...
frostauth::AssertionResult off = app->CheckOffline();
if (!off.ok) std::cout << "offline: " << off.reason << "\n";
// ...
app->StopHeartbeat();
app->Logout();
```

## SDK layout

- `frostauth.hpp` and `frostauth.cpp` contain the SDK. Link libsodium and WinHTTP (`ws2_32`) on Windows, or libsodium and libcurl elsewhere.
- `examples/console_main.cpp` is the interactive demo.
