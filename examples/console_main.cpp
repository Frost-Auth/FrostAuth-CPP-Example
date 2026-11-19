// FrostAuth C++ SDK — console example. Mirrors sdk/example.mjs output.
// Fill owner/product from your dashboard; set version to the build you ship.
#include "frostauth.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#endif

using namespace frostauth;

static void Fail(const FrostAuthError& e) {
    std::cout << "An error occurred: " << e.what() << "\n";
    std::exit(1);
}

static std::string Ask(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) std::exit(0);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

/// Locale-style timestamp, e.g. 9/16/2026, 6:08:02 PM (local zone, like JS
/// Date#toLocaleString()).
static std::string Loc(const std::string& iso) {
    if (iso.empty()) return "unknown";
    std::tm tm{};
    int ms = 0;
    // Parse "YYYY-MM-DDTHH:MM:SS(.fff)?(Z|±HH:MM)?"
    if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d.%d", &tm.tm_year, &tm.tm_mon,
                    &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &ms) < 6) {
        return "unknown";
    }
    tm.tm_mon -= 1;
    tm.tm_year -= 1900;
    tm.tm_isdst = -1;

    // Timezone suffix handling: Z / ±HH:MM → convert to time_t, then localtime.
    std::time_t epoch;
#ifdef _WIN32
    epoch = _mkgmtime(&tm);
#else
    epoch = timegm(&tm);
#endif
    if (epoch == static_cast<std::time_t>(-1)) return "unknown";

    // Apply the suffix offset (Z = 0; else parse ±HH:MM).
    auto zpos = iso.find('Z', 19);
    auto ppos = iso.find_first_of("+-", 19);
    if (zpos == std::string::npos && ppos != std::string::npos) {
        int oh = 0, om = 0;
        char sign = iso[ppos];
        if (std::sscanf(iso.c_str() + ppos, "%c%d:%d", &sign, &oh, &om) == 3) {
            long long off = static_cast<long long>(oh) * 3600 + om * 60;
            epoch += (sign == '-') ? off : -off;
        }
    }

    std::tm local{};
#ifdef _WIN32
    if (localtime_s(&local, &epoch) != 0) return "unknown";
#else
    if (localtime_r(&epoch, &local) == nullptr) return "unknown";
#endif
    int h12 = local.tm_hour % 12;
    if (h12 == 0) h12 = 12;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%d/%d/%d, %d:%02d:%02d %s",
                  local.tm_mon + 1, local.tm_mday, local.tm_year + 1900,
                  h12, local.tm_min, local.tm_sec,
                  local.tm_hour < 12 ? "AM" : "PM");
    return buf;
}

/// Value as JS would print it (unquoted strings, true/false, numbers plain).
static std::string Js(const Json* v, const char* fallback = "unknown") {
    if (!v || v->is_null()) return fallback;
    if (v->is_string()) return v->string;
    if (v->type == Json::Type::Bool) return v->boolean ? "true" : "false";
    return v->dump();
}

static const Json* Sub(const Json& snap, const char* section, const char* key) {
    const Json* sec = snap.find(section);
    return sec ? sec->find(key) : nullptr;
}

/// Days from now until an ISO-8601 timestamp (ceil), 0 when past, -1 when
/// unparseable. Same parsing rules as Loc (Z / ±HH:MM suffix aware).
static long DaysUntil(const std::string& iso) {
    if (iso.empty()) return -1;
    std::tm tm{};
    int ms = 0;
    if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d.%d", &tm.tm_year, &tm.tm_mon,
                    &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &ms) < 6) {
        return -1;
    }
    tm.tm_mon -= 1;
    tm.tm_year -= 1900;
    tm.tm_isdst = -1;
    std::time_t epoch;
#ifdef _WIN32
    epoch = _mkgmtime(&tm);
#else
    epoch = timegm(&tm);
#endif
    if (epoch == static_cast<std::time_t>(-1)) return -1;
    auto zpos = iso.find('Z', 19);
    auto ppos = iso.find_first_of("+-", 19);
    if (zpos == std::string::npos && ppos != std::string::npos) {
        int oh = 0, om = 0;
        char sign = iso[ppos];
        if (std::sscanf(iso.c_str() + ppos, "%c%d:%d", &sign, &oh, &om) == 3) {
            long long off = static_cast<long long>(oh) * 3600 + om * 60;
            epoch += (sign == '-') ? off : -off;
        }
    }
    long long diff = static_cast<long long>(epoch) - static_cast<long long>(std::time(nullptr));
    if (diff <= 0) return 0;
    return static_cast<long>((diff + 86399) / 86400);
}

/// Snapshot-backed profile readout. Everything here comes from the local
/// snapshot (populated by Activate/Register/Login on every plan), so it works
/// with or without a session token — unlike AppData/FetchOnline, which are
/// session-backed and fail on plans without tokenSystem.
/// Only prints fields the backend actually returns (licenseView + accountView
/// + device + product) — no invented email/key/plan lookups.
static void ShowUser(const Json& snap) {
    auto when = [](const std::string& iso) -> std::string {
        if (iso.empty()) return "—";
        std::string l = Loc(iso);
        return l == "unknown" ? std::string("—") : l;
    };
    std::string who = Js(snap.find("user"), "");
    if (who.empty()) who = Js(Sub(snap, "account", "username"), "");
    if (who.empty()) who = "unknown";
    std::string tier = Js(Sub(snap, "license", "tier"), "");
    if (tier.empty()) tier = "starter";
    std::string state = Js(Sub(snap, "license", "status"), "");
    if (state.empty()) state = "unknown";

    std::vector<Json> subs;
    if (const Json* s = snap.find("subscriptions"); s && s->is_array()) subs = s->array;
    std::string expiry = Js(Sub(snap, "license", "expiresAt"), "");
    if (expiry.empty()) {
        for (const Json& sub : subs) {
            if (const Json* ea = sub.find("expiresAt"); ea && ea->is_string() && !ea->string.empty()) {
                expiry = ea->string;
                break;
            }
        }
    }
    std::string validLine = "never";
    if (!expiry.empty()) {
        validLine = when(expiry);
        long days = DaysUntil(expiry);
        if (days >= 0) validLine += " (" + std::to_string(days) + "d left)";
    }

    std::string prodName = Js(Sub(snap, "product", "name"), "");
    if (prodName.empty()) prodName = "—";
    std::string prodVer = Js(Sub(snap, "product", "version"), "");
    std::string prodLine = prodName + (prodVer.empty() ? "" : " v" + prodVer);

    std::string used = Js(Sub(snap, "license", "devicesUsed"), "—");
    std::string devicesLine = used;
    const Json* unlim = Sub(snap, "license", "unlimitedDevices");
    const Json* lim = Sub(snap, "license", "deviceLimit");
    if (unlim && unlim->type == Json::Type::Bool && unlim->boolean) {
        devicesLine = used + " (unlimited)";
    } else if (lim && !lim->is_null()) {
        devicesLine = used + " / " + Js(lim);
    }

    std::string devLine = Js(Sub(snap, "device", "id"), "");
    if (devLine.empty()) devLine = "—";
    std::string ipLine = Js(Sub(snap, "account", "lastIp"), "");
    if (ipLine.empty()) ipLine = "—";

    std::cout << "\nSigned in as " << who << "\n";
    std::cout << "----------------------------------------------\n";
    std::cout << "  Licence ..... " << state << " (" << tier << ")\n";
    std::cout << "  IP Address .. " << ipLine << "\n";
    std::cout << "  Product ..... " << prodLine << "\n";
    std::cout << "  Devices ..... " << devicesLine << "\n";
    std::cout << "  Valid Until . " << validLine << "\n";
    std::cout << "  Device Id ... " << devLine << "\n";
    std::cout << "  First Seen .. " << when(Js(Sub(snap, "account", "createdAt"), "")) << "\n";
    std::cout << "  Last Seen ... " << when(Js(Sub(snap, "account", "lastLoginAt"), "")) << "\n";
    std::cout << "----------------------------------------------\n";
}

int main() {
    Options o;
    o.owner = "0809wkVP";
    o.product = "33abf48a-8e33-4df5-a4bd-d79195704d52";
    o.version = "1.0.2";
    // o.base_url = "https://api.frostauth.cc";

    std::shared_ptr<FrostAuthClient> app;
    try {
        app = FrostAuthClient::Create(std::move(o));
        app->Init();
    } catch (const FrostAuthError& e) {
        Fail(e);
    }

    std::cout << "[1] Login\n[2] Register\n[3] License\n[4] Upgrade\n";
    std::string option = Ask("Select an option: ");

    try {
        if (option == "1") {
            app->Login(Ask("Username: "), Ask("Password: "));
        } else if (option == "2") {
            app->Register(Ask("License: "), Ask("Username: "), Ask("Password: "));
        } else if (option == "3") {
            app->Activate(Ask("License: "));
        } else if (option == "4") {
            std::string username = Ask("Username: ");
            std::string password = Ask("Password: ");
            std::string license = Ask("License: ");
            app->Upgrade(username, password, license);
            std::cout << "Upgraded. Sign in to use the new licence.\n";
            app->Login(username, password);
        } else {
            std::cout << "Invalid option selected.\n";
            return 0;
        }
    } catch (const FrostAuthError& e) {
        Fail(e);
    }

    // ── Dashboard — snapshot-backed profile (+ webhook / build-hash) ─────────
    // Session-backed reads (AppData/online) are plan-gated (tokenSystem:
    // Developer/Pro) and print "unknown" on other plans, so they are not
    // shown here at all.
    Json snap = app->Snapshot();

    ShowUser(snap);
    std::cout << "\n";

    std::vector<Json> subs;
    if (const Json* s = snap.find("subscriptions"); s && s->is_array()) subs = s->array;
    for (size_t i = 0; i < subs.size(); ++i) {
        const Json& sub = subs[i];
        std::string tier = Js(sub.find("tier"), "");
        std::string name = !tier.empty() ? tier : Js(sub.find("status"), "");
        std::string expiry = "never";
        if (const Json* ea = sub.find("expiresAt"); ea && ea->is_string() && !ea->string.empty())
            expiry = Loc(ea->string);
        std::cout << "[" << (i + 1) << "/" << subs.size() << "] | Subscription: "
                  << name << " - Expiry: " << expiry << "\n";
    }

    std::string created = Js(Sub(snap, "account", "createdAt"));
    std::cout << "Created at: " << (created == "unknown" ? std::string("unknown") : Loc(created)) << "\n";
    std::string lastLogin = Js(Sub(snap, "account", "lastLoginAt"));
    std::cout << "Last Login: " << (lastLogin == "unknown" ? std::string("unknown") : Loc(lastLogin)) << "\n";
    std::string firstExpiry = "never";
    for (const Json& sub : subs) {
        if (const Json* ea = sub.find("expiresAt"); ea && ea->is_string() && !ea->string.empty()) {
            firstExpiry = Loc(ea->string);
            break;
        }
    }
    std::cout << "Expires: " << firstExpiry << "\n";

    try {
        Json res = app->Webhook("discord", "", "{\"content\":\"Hello from FrostAuth\"}");
        std::cout << "\nWebhook test: upstream " << Js(res.find("status"))
                  << " (ok: " << Js(res.find("ok")) << ")\n";
    } catch (const FrostAuthError& e) {
        std::cout << "\nWebhook test failed: " << e.code << " " << e.what() << "\n";
    }

    // Build-hash extra: hash THIS binary's contents when the product has
    // CHECK HASH enabled; pass it to Activate/Register/Login.
    std::cout << "\nBuild hash (this file):\n";
#ifdef _WIN32
    char path[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, path, MAX_PATH) > 0) {
        std::ifstream self(path, std::ios::binary);
        std::string selfHash = frostauth::Sha256HexFile(self);
        std::cout << "  " << selfHash << "\n";
        std::cout << "  Pass it to Activate/Register/Login (build_hash parameter) when the product requires it.\n";
    } else {
        std::cout << "  unavailable\n";
    }
#else
    std::ifstream self("/proc/self/exe", std::ios::binary);
    if (self) {
        std::cout << "  " << frostauth::Sha256HexFile(self) << "\n";
        std::cout << "  Pass it to Activate/Register/Login (build_hash parameter) when the product requires it.\n";
    } else {
        std::cout << "  unavailable\n";
    }
#endif

    std::cout << "\nClosing app in 10 seconds...\n";
    std::this_thread::sleep_for(std::chrono::seconds(10));
    try { app->Logout(); } catch (const FrostAuthError&) { /* already closed */ }
    return 0;
}
