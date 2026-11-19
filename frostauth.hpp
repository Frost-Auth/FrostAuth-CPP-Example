
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

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0.0;
    std::string string;
    std::vector<Json> array;
    std::vector<std::pair<std::string, Json>> object;

    static Json parse(const std::string& text);
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

using JsonPtr = std::shared_ptr<Json>;

std::string Sha256HexFile(std::istream& stream);

struct AssertionResult {
    bool ok = false;
    std::string reason;
    Json claims;
};

AssertionResult VerifyAssertion(const std::string& assertion, const std::map<std::string, std::vector<unsigned char>>& pins, const std::string& hwid);

std::string HardwareId(const std::string& scope);

std::pair<std::vector<std::pair<std::string, std::string>>, bool> HardwareProfile();

Json SnapshotOf(const class FrostAuthClient& client);

struct Options {
    std::string owner;
    std::string product;
    std::string version;
    std::string base_url;
    int timeout_ms = 10'000;
    int retries = 2;
    long offline_grace_seconds = 900;
    bool allow_insecure = false;
    bool allow_private_dns = false;
    std::string hardware_id_override;
    bool collect_hardware = true;
};

class FrostAuthClient {
public:
    std::function<void(const Json&)> on_activated;
    std::function<void(const Json&)> on_logged_in;
    std::function<void(const Json&)> on_validated;
    std::function<void(const std::string& current, const std::string& latest)> on_update_available;
    std::function<void(const FrostAuthError&, long seconds_offline, bool assertion_verified)> on_offline;
    std::function<void(const FrostAuthError&)> on_invalid;
    std::function<void(const FrostAuthError&)> on_needs_activation;

    static std::shared_ptr<FrostAuthClient> Create(Options o);

    ~FrostAuthClient();

    Json Init();

    Json Activate(const std::string& key, const std::string& build_hash = {}, const std::string& label = {});

    Json Register(const std::string& key, const std::string& username, const std::string& password, const std::string& build_hash = {}, const std::string& label = {});

    Json Login(const std::string& username, const std::string& password, const std::string& twofa = {}, const std::string& build_hash = {}, const std::string& label = {});

    Json Upgrade(const std::string& username, const std::string& password, const std::string& key);

    Json Logout();

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
    Json Webhook(const std::string& web_id, const std::string& params = {}, const std::string& body = {}, const std::string& conttype = {});
    Json AppData();
    std::vector<unsigned char> File(const std::string& file_id);

    Json Validate();

    void StartHeartbeat(int interval_seconds = 0);
    void StopHeartbeat();

    void Close();

    AssertionResult CheckOffline();

    Json Snapshot() const;

private:
    FrostAuthClient() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;

    Json AuthedCall(const std::string& method, const std::string& path, const Json* body);
};

}
