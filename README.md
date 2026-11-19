# FrostAuth-CPP-Example 🌟

FrostAuth C++ example SDK for https://www.frostauth.cc license key API auth.

This example ships the SDK source directly — `frostauth.hpp` + `frostauth.cpp`.
Copy those two files into your own project, link libsodium, and you're integrated.
No prebuilt binaries, no submodule step.

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, compiler, and the exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
build steps below don't make sense yet, learn some C++ first (Google/YouTube),
then come back. You'll need it for everything after integration too.

## Security practices

* Ship releases through an obfuscator/protector (VMProtect, Themida) and use
their SDK markers on license checks, not just the installer.
* Run frequent integrity checks so patched memory (.text hooks, detours) kills
the session instead of granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server already re-checks the
license on each call — don't add a local "isValid" boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks are what stop
tampering; the API only stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

* You may not offer this SDK (or a modified copy of it) to third parties as a
hosted or managed service that reproduces any substantial part of FrostAuth.
* You may not move, change, disable, or circumvent the license-key
functionality in the SDK, and you may not remove or obscure any license-key
enforcement it performs.
* You may not remove or obscure any licensing, copyright, or attribution
notices in the SDK files.

Thank you for your compliance — this SDK is a large body of work, and keeping
the notices intact is what keeps it free.

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for
[C++](https://www.frostauth.cc) (this repo), C#, Python, Go, Rust, Java, and
JavaScript. Come ask questions on Discord: https://www.frostauth.cc/discord

## Requirements

* CMake 3.20+, Ninja, a C++17 compiler
* libsodium — Windows: `vcpkg install libsodium:x64-mingw-static`
(linux: `apt install libsodium-dev`, macOS: `brew install libsodium`)
* Windows HTTP goes through WinHTTP (no extra dep). Linux/macOS link libcurl.

## Build

```bash
cd FrostAuth-CPP-Example
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/frostauth-console.exe
```

The CMake auto-detects a vcpkg libsodium install (`C:/vcpkg` or `%VCPKG_ROOT%`).
To pin the toolchain yourself:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=<vcpkg-root>/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_TARGET_TRIPLET=x64-mingw-static
cmake --build build
```

## `FrostAuthClient` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`examples/console_main.cpp`](examples/console_main.cpp):

```cpp
frostauth::Options o;
o.owner = "YOUR-OWNER-ID";       // dashboard → product → owner id
o.product = "YOUR-PRODUCT-ID";   // dashboard → product → product id
o.version = "1.0.0";             // must match the version you ship
// o.base_url = "https://api.frostauth.cc";  // default, only override for self-hosting

auto app = frostauth::FrostAuthClient::Create(std::move(o));
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```cpp
try {
    app->Init();
} catch (const frostauth::FrostAuthError& e) {
    std::cout << "Init failed: " << e.what() << "\n";
    return 1;
}
```

## Display application information

```cpp
frostauth::Json appData = app->AppData();
const frostauth::Json* prod = appData.find("product");
std::cout << "App Version: " << (prod ? prod->str_or("version") : "?") << "\n";
std::cout << "Customer panel: " << (prod ? "enabled" : "unknown") << "\n";
std::cout << "Keys: " << appData.str_or("numKeys") << "\n";
std::cout << "Users: " << appData.str_or("numUsers") << "\n";
```

## Check session validation

Use this to re-check the license/session with the server. Falls back from a
stale session token to the stored license key once.

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

Checks whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

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

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```cpp
std::string username = Ask("Username: ");
std::string password = Ask("Password: ");
std::string key = Ask("License: ");
app->Upgrade(username, password, key);
std::cout << "Upgraded. Sign in to use the new licence.\n";
app->Login(username, password);
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

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

Everything about the current session lives in the snapshot:

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

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

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

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```cpp
std::string motd = app->Variable("maintenance_message");
std::cout << "MOTD: " << motd << "\n";
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```cpp
frostauth::Json all = app->ListVars();                       // every variable on this user
frostauth::Json theme = app->GetVar("theme");                // one variable: theme.json value
app->SetVar("theme", "dark");                                // write it back
std::cout << "theme: " << theme.str_or("value") << "\n";
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```cpp
app->Log("client started, integrity check passed");
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```cpp
app->Ban("debugger detected");
```

With a reason (shown to the user on next login, visible on the dashboard):

```cpp
app->Ban("memory patch detected at 0x140001000");
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```cpp
frostauth::Json res = app->Webhook("discord", "", "{\"content\":\"Hello from FrostAuth\"}");
std::cout << "upstream " << res.str_or("status") << " (ok: " << res.dump() << ")\n";
```

## Download file

> Currently disabled server-side (route unmounted). `File()` throws
> `File downloads are disabled on this server` until file storage ships.
> The snippet below is the integration pattern for when it lands.

Files are operator-uploaded blobs (configs, scripts, DLLs) pinned per product,
tier- and version-gated. The SDK verifies the SHA-256 before returning.

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

Lets a signed-in user rename themselves (password re-checked server-side).

```cpp
std::string name = Ask("New username: ");
frostauth::Json res = app->ChangeUsername(name, Ask("Password: "));
std::cout << "Renamed to " << res.str_or("username") << "\n";
```

## Heartbeat & offline

`Validate()` on a timer keeps the session fresh. The SDK also caches a signed
offline assertion — when the network drops, `CheckOffline()` verifies it
locally so the app keeps working inside the grace window instead of hard-exiting.

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

* `frostauth.hpp` / `frostauth.cpp` — the whole SDK. Copy both, link
libsodium + WinHTTP (`ws2_32`) on Windows or libcurl elsewhere.
* `examples/console_main.cpp` — the interactive demo this README walks through.
