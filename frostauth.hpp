// FrostAuth SDK — C++ port. Public API.
//
// Mirrors sdk/frostauth.js wire behavior: every response is Ed25519-verified
// over "timestamp\nnonce\nmethod\npath\nstatus\nbody" (±60s skew, pinned key
// IDs), init() pins the server key against the key baked into this build,
// offline assertions are verified locally when the network is gone, and a
// DNS-hijack tripwire refuses loopback/private answers before any licence
// material is sent.
//
// Dependencies: libsodium (Ed25519), WinHTTP (Windows) or libcurl (other OS).

#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace frostauth {

inline constexpr const char* kSdkVersion = "1.0.0";
inline constexpr const char* kDefaultBaseUrl = "https://api.frostauth.cc";

/// Error codes for switch-style handling.
struct Code {
    static constexpr const char* Config = "CONFIG";
    static constexpr const char* Network = "NETWORK";
    static constexpr const char* Timeout = "TIMEOUT";
    static constexpr const char* NotInitialized = "NOT_INITIALIZED";
    static constexpr const char* NotActivated = "NOT_ACTIVATED";
    static constexpr const char* ServerError = "SERVER_ERROR";
    static constexpr const char* Signature = "SIGNATURE";
    static constexpr const char* RateLimited = "RATE_LIMITED";
};

/// Error thrown (as std::runtime_error subclass) by every SDK call.
class FrostAuthError : public std::runtime_error {
public:
    FrostAuthError(std::string message, std::string code, int status, bool retryable)
        : std::runtime_error(message), code(std::move(code)), status(status), retryable(retryable) {}

    std::string code;
    int status;
    bool retryable;

    bool needs_activation() const { return status == 404 && !retryable; }
    bool terminal() const { return !retryable && !needs_activation() && status >= 400 && status < 500; }
};

/// Minimal JSON value (object/array/string/number/bool/null). Parse + serialize.
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string string;
    std::vector<Json> array;
    std::vector<std::pair<std::string, Json>> object;   // insertion-ordered

    static Json parse(const std::string& text);          // throws FrostAuthError on bad input
    std::string dump() const;

    bool is_null() const { return type == Type::Null; }
    bool is_object() const { return type == Type::Object; }
    bool is_array() const { return type == Type::Array; }
    bool is_string() const { return type == Type::String; }
    bool is_number() const { return type == Type::Number; }

    const Json* find(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        for (auto& [k, v] : object) if (k == key) return &v;
        return nullptr;
    }
    std::string str_or(const std::string& key, const char* fallback = "") const {
        auto* v = find(key);
        return v && v->is_string() ? v->string : fallback;
    }
    void set(std::string key, Json value) { object.emplace_back(std::move(key), std::move(value)); }

    static Json Str(std::string s) { Json v; v.type = Type::String; v.string = std::move(s); return v; }
    static Json Bool(bool b) { Json v; v.type = Type::Bool; v.boolean = b; return v; }
    static Json Num(double d) { Json v; v.type = Type::Number; v.number = d; return v; }
    static Json parse_checked(const std::string& text) { return parse(text); }
};

/// Minimal raw-JSON request/response container for session state.
using JsonPtr = std::shared_ptr<Json>;

/// SHA-256 of a stream's remaining bytes, hex-encoded (used for build-hash
/// checks: hash your own binary/file and pass it to Activate/Register/Login).
std::string Sha256HexFile(std::istream& stream);

/// Result of VerifyAssertion / CheckOffline.
struct AssertionResult {
    bool ok = false;
    std::string reason;
    Json claims;   // valid claims on signature success
};

/// Verifies a server-issued offline assertion against pinned raw Ed25519 keys
/// (map keyId -> 32 raw bytes). Fails closed on unreadable/inverted windows.
AssertionResult VerifyAssertion(const std::string& assertion,
                                const std::map<std::string, std::vector<unsigned char>>& pins,
                                const std::string& hwid);

/// Scoped SHA-256 of the machine id — the raw id never leaves the device.
std::string HardwareId(const std::string& scope);

/// (components, virtual) advisory anti-clone data; values are hex hashes.
std::pair<std::vector<std::pair<std::string, std::string>>, bool> HardwareProfile();

/// Snapshot of client state (same shape as the JS SDK's snapshot()).
Json SnapshotOf(const class FrostAuthClient& client);

struct Options {
    std::string owner;
    std::string product;
    std::string version;
    std::string base_url;             // empty => kDefaultBaseUrl
    int timeout_ms = 10'000;
    int retries = 2;
    long offline_grace_seconds = 900;
    bool allow_insecure = false;      // allow http to non-loopback
    bool allow_private_dns = false;   // skip the DNS-hijack tripwire
    std::string hardware_id_override; // empty => derive from machine
    bool collect_hardware = true;
};

/// The FrostAuth client. Create with FrostAuthClient::Create, then Init().
class FrostAuthClient {
public:
    /// Event hooks. Assign before StartHeartbeat; called from heartbeat thread.
    std::function<void(const Json&)> on_activated;
    std::function<void(const Json&)> on_logged_in;
    std::function<void(const Json&)> on_validated;
    std::function<void(const std::string& current, const std::string& latest)> on_update_available;
    std::function<void(const FrostAuthError&, long seconds_offline, bool assertion_verified)> on_offline;
    std::function<void(const FrostAuthError&)> on_invalid;
    std::function<void(const FrostAuthError&)> on_needs_activation;

    /// Validates options and builds the client. Throws FrostAuthError on bad config.
    static std::shared_ptr<FrostAuthClient> Create(Options o);

    ~FrostAuthClient();

    /// Fetches the public catalog and pins the server's signing key (TOFU).
    Json Init();

    /// Binds a licence key to this machine and opens a session.
    Json Activate(const std::string& key, const std::string& build_hash = {},
                  const std::string& label = {});

    /// Creates an app user from a licence key, then opens a session.
    Json Register(const std::string& key, const std::string& username,
                  const std::string& password, const std::string& build_hash = {},
                  const std::string& label = {});

    /// Signs in an app user and opens a session.
    Json Login(const std::string& username, const std::string& password,
               const std::string& twofa = {}, const std::string& build_hash = {},
               const std::string& label = {});

    /// Attaches a licence key to an existing app user (no session opened).
    Json Upgrade(const std::string& username, const std::string& password, const std::string& key);

    /// Invalidates the session server-side and closes the client.
    Json Logout();

    /// Re-fetches and adopts current session state.
    Json Session();

    std::string Variable(const std::string& key);
    Json ListVars();
    Json GetVar(const std::string& key);
    Json SetVar(const std::string& key, const std::string& value);
    Json ChangeUsername(const std::string& username, const std::string& password);
    Json Log(const std::string& message);
    Json Ban(const std::string& reason = {});
    Json FetchOnline();
    Json CheckBlacklist();
    Json Webhook(const std::string& web_id, const std::string& params = {},
                 const std::string& body = {}, const std::string& conttype = {});
    Json AppData();
    /// File download by handle. Currently disabled server-side (route
    /// unmounted) — mirrors the JS reference SDK, which throws.
    std::vector<unsigned char> File(const std::string& file_id);

    /// Re-checks the licence/session with the server; falls back from a stale
    /// session token to the stored licence key once.
    Json Validate();

    /// Validates periodically (server cadence or explicit seconds) until Stop/Close.
    void StartHeartbeat(int interval_seconds = 0);
    void StopHeartbeat();

    /// Tears down the client and drops the offline assertion.
    void Close();

    /// Verifies the last server-issued assertion locally.
    AssertionResult CheckOffline();

    /// Point-in-time client state.
    Json Snapshot() const;

private:
    FrostAuthClient() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;

    /// Shared helper for session-scoped calls (throws NotActivated without one).
    Json AuthedCall(const std::string& method, const std::string& path, const Json* body);
};

}  // namespace frostauth
