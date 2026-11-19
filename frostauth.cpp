#include "frostauth.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <sodium.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <winhttp.h>
#else
#  include <curl/curl.h>
#  include <arpa/inet.h>
#  include <ifaddrs.h>
#  include <netdb.h>
#  include <unistd.h>
#endif

namespace frostauth {


static std::string ToHex(const unsigned char* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0xF]);
    }
    return out;
}

static std::string Sha256Hex(const std::string& input) {
    unsigned char hash[32];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    return ToHex(hash, 32);
}

static std::string Facet(const std::string& v) { return Sha256Hex(v).substr(0, 32); }

std::string Sha256HexFile(std::istream& stream) {
    unsigned char hash[32];
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    char buf[8192];
    while (stream.read(buf, sizeof(buf)) || stream.gcount() > 0) {
        crypto_hash_sha256_update(&state, reinterpret_cast<const unsigned char*>(buf), static_cast<unsigned long long>(stream.gcount()));
    }
    crypto_hash_sha256_final(&state, hash);
    return ToHex(hash, 32);
}

static std::string B64uEncode(const unsigned char* data, std::size_t len) {
    const std::size_t b64len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string buf(b64len, '\0');
    char* out = sodium_bin2base64(buf.data(), b64len, data, len, sodium_base64_VARIANT_ORIGINAL);
    std::string s(out);
    std::replace(s.begin(), s.end(), '+', '-');
    std::replace(s.begin(), s.end(), '/', '_');
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

static std::vector<unsigned char> B64uDecode(const std::string& in) {
    std::string s = in;
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    while (s.size() % 4) s.push_back('=');
    std::size_t binlen = 0;
    std::vector<unsigned char> out(s.size() / 4 * 3 + 3);
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &binlen, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw FrostAuthError("not a usable base64url value", Code::Config, 0, false);
    }
    out.resize(binlen);
    return out;
}

static long long NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::vector<unsigned char> SpkiToRaw(const std::string& b64) {
    auto der = B64uDecode(b64);
    if (der.size() != 44) {
        throw FrostAuthError("not a usable Ed25519 public key", Code::Config, 0, false);
    }
    return std::vector<unsigned char>(der.begin() + 12, der.end());
}

static std::string Trunc(const std::string& s, std::size_t n) {
    return s.size() <= n ? s : s.substr(0, n);
}

static std::string UrlEscape(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}


namespace {

class JsonParser {
public:
    explicit JsonParser(const std::string& s) : s_(s) {}

    Json Parse() {
        SkipWs();
        Json v = ParseValue();
        SkipWs();
        if (pos_ != s_.size()) Fail("trailing data");
        return v;
    }

private:
    const std::string& s_;
    std::size_t pos_ = 0;

    [[noreturn]] void Fail(const char* msg) {
        throw FrostAuthError(std::string("json: ") + msg, Code::ServerError, 0, false);
    }

    void SkipWs() {
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_; else break;
        }
    }

    char Peek() {
        if (pos_ >= s_.size()) Fail("unexpected end of input");
        return s_[pos_];
    }

    void Expect(char c) {
        SkipWs();
        if (pos_ >= s_.size() || s_[pos_] != c) Fail("unexpected character");
        ++pos_;
    }

    Json ParseValue() {
        SkipWs();
        char c = Peek();
        switch (c) {
            case '{': return ParseObject();
            case '[': return ParseArray();
            case '"': {
                Json v; v.type = Json::Type::String; v.string = ParseString(); return v;
            }
            case 't': ExpectWord("true");  { Json v; v.type = Json::Type::Bool; v.boolean = true;  return v; }
            case 'f': ExpectWord("false"); { Json v; v.type = Json::Type::Bool; v.boolean = false; return v; }
            case 'n': ExpectWord("null");  return Json{};
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    Json v; v.type = Json::Type::Number; v.number = ParseNumber(); return v;
                }
                Fail("unexpected character");
        }
    }

    void ExpectWord(const char* w) {
        std::size_t n = std::strlen(w);
        if (s_.compare(pos_, n, w) != 0) Fail("bad literal");
        pos_ += n;
    }

    Json ParseObject() {
        Expect('{');
        Json v; v.type = Json::Type::Object;
        SkipWs();
        if (Peek() == '}') { ++pos_; return v; }
        while (true) {
            SkipWs();
            std::string key = ParseString();
            Expect(':');
            v.object.emplace_back(std::move(key), ParseValue());
            SkipWs();
            char c = Peek();
            if (c == ',') { ++pos_; continue; }
            if (c == '}') { ++pos_; return v; }
            Fail("expected ',' or '}'");
        }
    }

    Json ParseArray() {
        Expect('[');
        Json v; v.type = Json::Type::Array;
        SkipWs();
        if (Peek() == ']') { ++pos_; return v; }
        while (true) {
            v.array.push_back(ParseValue());
            SkipWs();
            char c = Peek();
            if (c == ',') { ++pos_; continue; }
            if (c == ']') { ++pos_; return v; }
            Fail("expected ',' or ']'");
        }
    }

    std::string ParseString() {
        Expect('"');
        std::string out;
        while (true) {
            if (pos_ >= s_.size()) Fail("unterminated string");
            char c = s_[pos_++];
            if (c == '"') return out;
            if (c == '\\') {
                if (pos_ >= s_.size()) Fail("bad escape");
                char e = s_[pos_++];
                switch (e) {
                    case '"':  out.push_back('"');  break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/');  break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'n':  out.push_back('\n'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) Fail("bad \\u escape");
                        unsigned code = std::stoul(s_.substr(pos_, 4), nullptr, 16);
                        pos_ += 4;
                        if (code < 0x80) {
                            out.push_back(static_cast<char>(code));
                        } else if (code < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        }
                        break;
                    }
                    default: Fail("bad escape");
                }
            } else {
                out.push_back(c);
            }
        }
    }

    double ParseNumber() {
        std::size_t start = pos_;
        if (Peek() == '-') ++pos_;
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') ++pos_;
            else break;
        }
        return std::stod(s_.substr(start, pos_ - start));
    }
};

void DumpString(const std::string& s, std::string& out) {
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

void DumpValue(const Json& v, std::string& out) {
    switch (v.type) {
        case Json::Type::Null:   out += "null"; break;
        case Json::Type::Bool:   out += v.boolean ? "true" : "false"; break;
        case Json::Type::Number: {
            if (std::floor(v.number) == v.number &&
                std::abs(v.number) < 9.0e15) {
                out += std::to_string(static_cast<long long>(v.number));
            } else {
                std::ostringstream oss;
                oss << v.number;
                out += oss.str();
            }
            break;
        }
        case Json::Type::String: DumpString(v.string, out); break;
        case Json::Type::Array: {
            out.push_back('[');
            for (std::size_t i = 0; i < v.array.size(); ++i) {
                if (i) out.push_back(',');
                DumpValue(v.array[i], out);
            }
            out.push_back(']');
            break;
        }
        case Json::Type::Object: {
            out.push_back('{');
            for (std::size_t i = 0; i < v.object.size(); ++i) {
                if (i) out.push_back(',');
                DumpString(v.object[i].first, out);
                out.push_back(':');
                DumpValue(v.object[i].second, out);
            }
            out.push_back('}');
            break;
        }
    }
}

}

Json Json::parse(const std::string& text) {
    if (text.empty()) return Json{};
    return JsonParser(text).Parse();
}

std::string Json::dump() const {
    std::string out;
    DumpValue(*this, out);
    return out;
}


namespace {

std::string ClaimField(const Json& claims, const char* key) {
    auto* v = claims.find(key);
    return v && v->is_string() ? v->string : "";
}

std::string ClaimString(const Json& claims) {
    std::string out = "frostauth:assertion:v1\n1";
    for (const char* f : {"lic", "pid", "dev", "hwid", "status", "tier", "exp", "iat", "nbf", "naf"}) {
        out.push_back('\n');
        out += ClaimField(claims, f);
    }
    return out;
}

bool ParseMs(const Json& v, long long& out) {
    if (v.type == Json::Type::Number) { out = static_cast<long long>(v.number); return true; }
    if (v.type != Json::Type::String || v.string.empty()) return false;
    const std::string& s = v.string;
    if (s.size() >= 20 && s[4] == '-' && s[7] == '-' && s[10] == 'T') {
        unsigned y, mo, d, h, mi, sec;
        if (std::sscanf(s.c_str(), "%4u-%2u-%2uT%2u:%2u:%2u", &y, &mo, &d, &h, &mi, &sec) == 6) {
            std::tm tm{};
            tm.tm_year = static_cast<int>(y) - 1900;
            tm.tm_mon = static_cast<int>(mo) - 1;
            tm.tm_mday = static_cast<int>(d);
            tm.tm_hour = static_cast<int>(h);
            tm.tm_min = static_cast<int>(mi);
            tm.tm_sec = static_cast<int>(sec);
            int ms = 0;
            auto dot = s.find('.', 19);
            if (dot != std::string::npos && dot + 1 < s.size()) {
                ms = std::atoi(s.c_str() + dot + 1);
            }
#ifdef _WIN32
            time_t t = _mkgmtime(&tm);
#else
            time_t t = timegm(&tm);
#endif
            if (t == static_cast<time_t>(-1)) return false;
            out = static_cast<long long>(t) * 1000 + ms;
            return true;
        }
    }
    return false;
}

}

AssertionResult VerifyAssertion(const std::string& assertion, const std::map<std::string, std::vector<unsigned char>>& pins, const std::string& hwid) {
    AssertionResult r;
    if (pins.empty()) { r.reason = "no pinned public key"; return r; }

    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        auto dot = assertion.find('.', start);
        parts.push_back(assertion.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    if (parts.size() != 3) { r.reason = "malformed"; return r; }
    const std::string& payload = parts[0];
    const std::string& sigB64 = parts[1];
    const std::string& keyId = parts[2];

    std::vector<const unsigned char*> candidates;
    for (auto& [id, raw] : pins) {
        if (keyId.empty() || id == keyId) candidates.push_back(raw.data());
    }
    if (candidates.empty()) {
        r.reason = "signed with key \"" + keyId + "\", which this build does not trust";
        return r;
    }

    Json claims;
    std::vector<unsigned char> signature;
    try {
        auto payloadBytes = B64uDecode(payload);
        claims = Json::parse(std::string(payloadBytes.begin(), payloadBytes.end()));
        signature = B64uDecode(sigB64);
    } catch (const FrostAuthError&) {
        r.reason = "unreadable";
        return r;
    }

    std::string material = ClaimString(claims);
    bool ok = false;
    for (auto* key : candidates) {
        if (crypto_sign_verify_detached(signature.data(), reinterpret_cast<const unsigned char*>(material.data()), material.size(), key) == 0) {
            ok = true;
            break;
        }
    }
    if (!ok) { r.reason = "signature does not verify"; r.claims = claims; return r; }

    if (!hwid.empty() && ClaimField(claims, "hwid") != hwid) {
        r.reason = "issued for a different machine";
        r.claims = claims;
        return r;
    }

    long long nbf = 0, naf = 0;
    auto* nbfV = claims.find("nbf");
    auto* nafV = claims.find("naf");
    bool haveNbf = nbfV && ParseMs(*nbfV, nbf);
    bool haveNaf = nafV && ParseMs(*nafV, naf);
    if (!haveNbf || !haveNaf || naf <= nbf) {
        r.reason = "offline window is missing or unreadable";
        r.claims = claims;
        return r;
    }
    long long at = NowMs();
    if (at < nbf) { r.reason = "not yet valid"; r.claims = claims; return r; }
    if (at > naf) { r.reason = "offline period has run out"; r.claims = claims; return r; }

    auto* expV = claims.find("exp");
    if (expV && !expV->is_null() &&
        !(expV->is_string() && expV->string.empty())) {
        long long exp = 0;
        if (!ParseMs(*expV, exp) || at > exp) {
            r.reason = "licence expired";
            r.claims = claims;
            return r;
        }
    }
    r.ok = true;
    r.claims = claims;
    return r;
}


#ifdef _WIN32
static std::string RunCommand(const std::string& cmdline, DWORD timeout_ms = 5000) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE readEnd = nullptr, writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) return {};
    SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writeEnd;
    si.hStdError = writeEnd;

    PROCESS_INFORMATION pi{};
    std::vector<char> cmd(cmdline.begin(), cmdline.end());
    cmd.push_back('\0');
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(readEnd); CloseHandle(writeEnd);
        return {};
    }
    CloseHandle(writeEnd);

    std::string out;
    char buf[4096];
    DWORD read = 0;
    DWORD elapsed = 0;
    while (elapsed < timeout_ms) {
        while (ReadFile(readEnd, buf, sizeof(buf), &read, nullptr) && read > 0) {
            out.append(buf, read);
        }
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) {
            while (ReadFile(readEnd, buf, sizeof(buf), &read, nullptr) && read > 0) {
                out.append(buf, read);
            }
            break;
        }
        elapsed += 200;
    }
    CloseHandle(readEnd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out;
}
#else
static std::string ReadFileIf(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    std::string out;
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    std::fclose(f);
    return out;
}
#endif

#ifdef _WIN32
static std::string RawMachineId() {
    static std::string cached;
    static bool done = false;
    if (done) return cached;
    auto out = RunCommand("reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid");
    auto pos = out.find("REG_SZ");
    if (pos != std::string::npos) {
        std::string val = out.substr(pos + 6);
        auto first = val.find_first_not_of(" \t\r\n");
        auto last = val.find_last_not_of(" \t\r\n");
        if (first != std::string::npos) cached = val.substr(first, last - first + 1);
    }
    if (cached.empty()) {
        char host[256] = {};
        DWORD sz = sizeof(host);
        if (!GetComputerNameA(host, &sz)) std::strcpy(host, "unknown");
        char user[256] = {};
        DWORD usz = sizeof(user);
        if (!GetUserNameA(user, &usz)) std::strcpy(user, "unknown");
        cached = std::string("fallback:") + host + ":" + user + ":windows";
    }
    done = true;
    return cached;
}
#else
static std::string RawMachineId() {
    static std::string cached;
    static bool done = false;
    if (done) return cached;
    std::string found = ReadFileIf("/etc/machine-id");
    if (found.empty()) found = ReadFileIf("/var/lib/dbus/machine-id");
    auto first = found.find_first_not_of(" \t\r\n");
    if (first != std::string::npos) {
        auto last = found.find_last_not_of(" \t\r\n");
        cached = found.substr(first, last - first + 1);
    }
    if (cached.empty()) {
        char host[256] = {};
        if (gethostname(host, sizeof(host)) != 0) std::strcpy(host, "unknown");
        char user[256] = {};
        if (getlogin_r(user, sizeof(user)) != 0) std::strcpy(user, "unknown");
        const char* os =
#ifdef __APPLE__
            "darwin";
#else
            "linux";
#endif
        cached = std::string("fallback:") + host + ":" + user + ":" + os;
    }
    done = true;
    return cached;
}
#endif

std::string HardwareId(const std::string& scope) {
    std::string s = scope.empty() ? "frostauth" : scope;
    return Sha256Hex(s + "|" + RawMachineId());
}

static const char* OsName() {
#ifdef _WIN32
    return "windows";
#elif defined(__APPLE__)
    return "darwin";
#else
    return "linux";
#endif
}

static const char* ArchName() {
#if defined(_M_X64) || defined(__x86_64__)
    return "x86_64";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#else
    return "unknown";
#endif
}

std::pair<std::vector<std::pair<std::string, std::string>>, bool> HardwareProfile() {
    std::vector<std::pair<std::string, std::string>> components;
    std::string cpu = "unknown";

#ifdef _WIN32
    auto out = RunCommand(
        "reg query HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0 /v ProcessorNameString");
    auto pos = out.find("REG_SZ");
    if (pos != std::string::npos) {
        std::string val = out.substr(pos + 6);
        auto first = val.find_first_not_of(" \t\r\n");
        auto last = val.find_last_not_of(" \t\r\n");
        if (first != std::string::npos) cpu = val.substr(first, last - first + 1);
    }
#elif defined(__APPLE__)
    std::FILE* f = popen("sysctl -n machdep.cpu.brand_string 2>/dev/null", "r");
    if (f) {
        char buf[512] = {};
        if (std::fgets(buf, sizeof(buf), f)) {
            std::string v(buf);
            auto first = v.find_first_not_of(" \t\r\n");
            auto last = v.find_last_not_of(" \t\r\n");
            if (first != std::string::npos) cpu = v.substr(first, last - first + 1);
        }
        pclose(f);
    }
#else
    std::string cpuinfo = ReadFileIf("/proc/cpuinfo");
    auto pos = cpuinfo.find("model name");
    if (pos != std::string::npos) {
        auto colon = cpuinfo.find(':', pos);
        if (colon != std::string::npos) {
            auto nl = cpuinfo.find('\n', colon);
            std::string v = cpuinfo.substr(colon + 1, nl == std::string::npos ? std::string::npos : nl - colon - 1);
            auto first = v.find_first_not_of(" \t");
            if (first != std::string::npos) cpu = v.substr(first);
        }
    }
#endif

    unsigned ncpu = std::thread::hardware_concurrency();
    components.emplace_back("cpu", Facet(cpu + "|" + std::to_string(ncpu)));
    components.emplace_back("ram", Facet("unknown"));
    components.emplace_back("arch", Facet(ArchName()));
    components.emplace_back("platform", Facet(OsName()));
#ifdef _WIN32
    char host[256] = {};
    DWORD sz = sizeof(host);
    if (!GetComputerNameA(host, &sz)) std::strcpy(host, "unknown");
    components.emplace_back("host", Facet(host));
#else
    char host[256] = {};
    if (gethostname(host, sizeof(host)) != 0) std::strcpy(host, "unknown");
    components.emplace_back("host", Facet(host));
#endif

    auto lower = cpu;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const char* vmHints[] = {"vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "hyper-v", "hyperv", "parallels", "bhyve", "virtual machine", "innotek"};
    bool vm = false;
    for (auto* hint : vmHints) {
        if (lower.find(hint) != std::string::npos) { vm = true; break; }
    }
    return {components, vm};
}


namespace {

std::string HostOf(const std::string& url) {
    std::string rest = url;
    for (const char* prefix : {"https://", "http://"}) {
        if (rest.rfind(prefix, 0) == 0) {
            rest = rest.substr(std::strlen(prefix));
            break;
        }
    }
    auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    auto colon = rest.find(':');
    if (colon != std::string::npos) rest = rest.substr(0, colon);
    return rest;
}

bool IsPrivateIpText(const std::string& host) {
#ifdef _WIN32
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    struct addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) return false;
    bool priv = false;
    for (auto* p = result; p; p = p->ai_next) {
        char ip[64] = {};
        getnameinfo(p->ai_addr, static_cast<socklen_t>(p->ai_addrlen),
            ip, sizeof(ip), nullptr, 0, NI_NUMERICHOST);
        std::string s(ip);
        if (s.rfind("127.", 0) == 0 || s.rfind("10.", 0) == 0 ||
            s.rfind("192.168.", 0) == 0 || s.rfind("169.254.", 0) == 0 ||
            s.rfind("0.", 0) == 0 ||
            (s.rfind("172.", 0) == 0 && s.size() > 6)) {
            int second = std::atoi(s.c_str() + 4);
            if (s.rfind("172.", 0) == 0) {
                if (second >= 16 && second <= 31) { priv = true; break; }
            } else {
                priv = true; break;
            }
        }
        if (s.rfind("fc", 0) == 0 || s.rfind("fd", 0) == 0 ||
            s.rfind("fe80", 0) == 0 || s == "::1" || s == "::") {
            priv = true; break;
        }
    }
    freeaddrinfo(result);
    return priv;
#else
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    struct addrinfo* result = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) return false;
    bool priv = false;
    for (auto* p = result; p; p = p->ai_next) {
        char ip[INET6_ADDRSTRLEN] = {};
        void* addr = p->ai_family == AF_INET
            ? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr)
            : static_cast<void*>(&reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr);
        inet_ntop(p->ai_family, addr, ip, sizeof(ip));
        std::string s(ip);
        if (s.rfind("127.", 0) == 0 || s.rfind("10.", 0) == 0 ||
            s.rfind("192.168.", 0) == 0 || s.rfind("169.254.", 0) == 0 ||
            s.rfind("0.", 0) == 0 || s == "::1" || s == "::" ||
            s.rfind("fc", 0) == 0 || s.rfind("fd", 0) == 0 || s.rfind("fe80", 0) == 0) {
            priv = true; break;
        }
        if (s.rfind("172.", 0) == 0) {
            int second = std::atoi(s.c_str() + 4);
            if (second >= 16 && second <= 31) { priv = true; break; }
        }
    }
    freeaddrinfo(result);
    return priv;
#endif
}

}


namespace {

struct HttpResponse {
    int status = 0;
    std::string body;
    std::map<std::string, std::string> headers;
};

}

#ifdef _WIN32
static bool UrlParts(const std::string& url, bool& https, std::wstring& hostW, INTERNET_PORT& port, std::wstring& pathW) {
    std::string rest = url;
    if (rest.rfind("https://", 0) == 0) { https = true; rest = rest.substr(8); }
    else if (rest.rfind("http://", 0) == 0) { https = false; rest = rest.substr(7); }
    else return false;
    std::string hostport = rest;
    std::string path = "/";
    auto slash = hostport.find('/');
    if (slash != std::string::npos) {
        path = hostport.substr(slash);
        hostport = hostport.substr(0, slash);
    }
    std::string host = hostport;
    port = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    auto colon = hostport.rfind(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = static_cast<INTERNET_PORT>(std::atoi(hostport.c_str() + colon + 1));
    }
    hostW.assign(host.begin(), host.end());
    pathW.assign(path.begin(), path.end());
    return true;
}

static HttpResponse WinHttpRoundTrip(
    const std::string& base_url, const std::string& method, const std::string& path,
    const std::string& body, const std::vector<std::pair<std::string, std::string>>& headers,
    int timeout_ms) {
    HttpResponse out;
    bool https = false;
    std::wstring hostW, pathW;
    INTERNET_PORT port = 0;
    if (!UrlParts(base_url + path, https, hostW, port, pathW)) {
        throw FrostAuthError("invalid base url", Code::Config, 0, false);
    }
    std::wstring full_path = pathW;

    HINTERNET session = WinHttpOpen(L"frostauth-sdk-cpp/1.0.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) throw FrostAuthError("could not reach the licence server", Code::Network, 0, true);
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET connect = WinHttpConnect(session, hostW.c_str(), port, 0);
    if (!connect) { WinHttpCloseHandle(session); throw FrostAuthError("could not reach the licence server", Code::Network, 0, true); }

    const wchar_t* verb = method == "GET" ? L"GET" : method == "POST" ? L"POST" : method == "PUT" ? L"PUT" : method == "PATCH" ? L"PATCH" : method == "DELETE" ? L"DELETE" : L"POST";
    HINTERNET request = WinHttpOpenRequest(connect, verb, full_path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
    if (!request) {
        WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        throw FrostAuthError("could not reach the licence server", Code::Network, 0, true);
    }

    std::wstring header_blob;
    for (auto& [k, v] : headers) {
        header_blob += std::wstring(k.begin(), k.end()) + L": " + std::wstring(v.begin(), v.end()) + L"\r\n";
    }
    header_blob += L"Content-Type: application/json\r\nAccept: application/json\r\n";

    const char* bodyPtr = body.empty() ? nullptr : body.data();
    DWORD bodyLen = static_cast<DWORD>(body.size());
    BOOL sent = WinHttpSendRequest(request, header_blob.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : header_blob.c_str(), static_cast<DWORD>(header_blob.size()), const_cast<char*>(bodyPtr), bodyLen, bodyLen, 0);
    if (sent && WinHttpReceiveResponse(request, nullptr)) {
        DWORD status = 0, size = sizeof(status);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
        out.status = static_cast<int>(status);

        for (const char* h : {"x-frost-signature", "x-frost-timestamp", "x-frost-nonce", "x-frost-key-id", "retry-after"}) {
            std::wstring nameW(h, h + std::strlen(h));
            DWORD hsize = 0;
            WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, nameW.c_str(), nullptr, &hsize, WINHTTP_NO_HEADER_INDEX);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && hsize > 0) {
                std::wstring val(hsize / 2, L'\0');
                if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, nameW.c_str(), val.data(), &hsize, WINHTTP_NO_HEADER_INDEX)) {
                    val.resize(hsize / 2);
                    out.headers[h] = std::string(val.begin(), val.end());
                }
            }
        }

        char buf[16384];
        DWORD bytes = 0;
        while (WinHttpReadData(request, buf, sizeof(buf), &bytes) && bytes > 0) {
            out.body.append(buf, bytes);
        }
    } else {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        throw FrostAuthError("could not reach the licence server", Code::Network, 0, true);
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return out;
}
#else
struct CurlSink { std::string body; };
static std::size_t CurlWrite(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* sink = static_cast<CurlSink*>(userdata);
    sink->body.append(ptr, size * nmemb);
    return size * nmemb;
}
static std::size_t CurlHeader(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
    std::string line(ptr, size * nmemb);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string k = line.substr(0, colon);
        std::string v = line.substr(colon + 1);
        auto trim = [](std::string& s) {
            auto f = s.find_first_not_of(" \t\r\n");
            auto l = s.find_last_not_of(" \t\r\n");
            s = f == std::string::npos ? "" : s.substr(f, l - f + 1);
        };
        std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        trim(k); trim(v);
        (*headers)[k] = v;
    }
    return size * nmemb;
}

static HttpResponse CurlRoundTrip(
    const std::string& base_url, const std::string& method, const std::string& path,
    const std::string& body, const std::vector<std::pair<std::string, std::string>>& headers,
    int timeout_ms) {
    HttpResponse out;
    CURL* curl = curl_easy_init();
    if (!curl) throw FrostAuthError("could not reach the licence server", Code::Network, 0, true);
    curl_easy_setopt(curl, CURLOPT_URL, (base_url + path).c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    curl_slist* hl = nullptr;
    std::string ct = "Content-Type: application/json";
    std::string acc = "Accept: application/json";
    hl = curl_slist_append(hl, ct.c_str());
    hl = curl_slist_append(hl, acc.c_str());
    for (auto& [k, v] : headers) hl = curl_slist_append(hl, (k + ": " + v).c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hl);

    if (method != "GET") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        }
    }

    CurlSink sink;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CurlHeader);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &out.headers);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        out.status = static_cast<int>(code);
        out.body = std::move(sink.body);
    }
    curl_slist_free_all(hl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        bool timeout = rc == CURLE_OPERATION_TIMEDOUT;
        throw FrostAuthError(timeout ? "request timed out" : "could not reach the licence server", timeout ? Code::Timeout : Code::Network, 0, true);
    }
    return out;
}
#endif

static HttpResponse HttpRoundTrip(
    const std::string& base_url, const std::string& method, const std::string& path,
    const std::string& body, const std::vector<std::pair<std::string, std::string>>& headers,
    int timeout_ms) {
#ifdef _WIN32
    return WinHttpRoundTrip(base_url, method, path, body, headers, timeout_ms);
#else
    return CurlRoundTrip(base_url, method, path, body, headers, timeout_ms);
#endif
}


struct FrostAuthClient::Impl {
    Options o;
    std::string base_url;
    std::map<std::string, std::vector<unsigned char>> keys;
    Json app, license, product, device, account;
    std::string user;
    std::vector<Json> subscriptions;
    Json session;
    std::string stored_key;
    std::string assertion;
    std::string offline_until;
    std::string machine_id;
    long long offline_since_ms = 0;
    bool has_offline_since = false;
    bool initialized = false;
    bool activated = false;
    bool closed = false;

    std::mutex mtx;
    std::thread heartbeat;
    std::atomic<bool> heartbeat_stop{false};

    std::string MachineId() {
        std::lock_guard<std::mutex> lk(mtx);
        if (!machine_id.empty()) return machine_id;
        machine_id = !o.hardware_id_override.empty()
            ? o.hardware_id_override
            : HardwareId(o.owner);
        return machine_id;
    }

    std::string Token() {
        if (session.is_object()) {
            auto* t = session.find("token");
            if (t && t->is_string()) return t->string;
        }
        return {};
    }

    void AdoptLocked(const Json& data) {
        if (!data.is_object()) return;
        if (auto* s = data.find("session"); s && s->is_object() && s->find("token")) session = *s;
        if (auto* v = data.find("license"); v && v->is_object()) license = *v;
        if (auto* v = data.find("product"); v && v->is_object()) {
            product = *v;
            if (auto* ua = v->find("updateAvailable"); ua && ua->type == Json::Type::Bool && ua->boolean) {
                std::string latest = v->str_or("latest");
                if (latest.empty()) latest = v->str_or("version");
            }
        }
        if (auto* v = data.find("device"); v && v->is_object()) device = *v;
        if (auto* v = data.find("user"); v && v->is_string()) user = v->string;
        if (auto* v = data.find("account"); v && v->is_object()) account = *v;
        if (auto* v = data.find("subscriptions"); v && v->is_array()) {
            subscriptions = v->array;
        }
        if (auto* v = data.find("offline"); v && v->is_object()) {
            if (auto* a = v->find("assertion"); a && a->is_string() && !a->string.empty()) {
                assertion = a->string;
                offline_until = v->str_or("notAfter");
            }
        }
    }

    Json SnapshotLocked() const {
        Json snap; snap.type = Json::Type::Object;
        snap.set("app", app);
        snap.set("license", license);
        snap.set("product", product);
        snap.set("device", device);
        Json u; u.type = Json::Type::String; u.string = user;
        snap.set("user", u);
        snap.set("account", account);
        Json subs; subs.type = Json::Type::Array; subs.array = subscriptions;
        snap.set("subscriptions", subs);
        Json v; v.type = Json::Type::Bool; v.boolean = activated && !closed;
        snap.set("valid", v);
        return snap;
    }

    void RequireInit() {
        std::lock_guard<std::mutex> lk(mtx);
        if (!initialized) {
            throw FrostAuthError("Call Init() before anything else", Code::NotInitialized, 0, false);
        }
    }

    void AssertRealHost() {
        if (o.allow_private_dns) return;
        std::string host = HostOf(base_url);
        if (host.empty() || host == "localhost" || host == "127.0.0.1" || host == "::1") return;
        bool ipLiteral = !host.empty() && (std::isdigit(static_cast<unsigned char>(host[0])) || host.find(':') != std::string::npos);
        if (ipLiteral) return;
        if (IsPrivateIpText(host)) {
            throw FrostAuthError(
                '"' + host + "\" resolves to loopback or private space — this is what a hosts-file hijack "
                "or licence emulator looks like. Refusing to continue.",
                Code::Network, 0, false);
        }
    }

    using Round = HttpResponse;

    Round OneRound(const std::string& method, const std::string& path, const std::string& body, const std::string& token) {
        unsigned char nonceBytes[16];
        randombytes_buf(nonceBytes, sizeof(nonceBytes));
        std::string nonce = B64uEncode(nonceBytes, sizeof(nonceBytes));
        long long now = NowMs();

        std::vector<std::pair<std::string, std::string>> headers;
        headers.emplace_back("User-Agent", std::string("frostauth-sdk-cpp/") + kSdkVersion + " (" + OsName() + ")");
        headers.emplace_back("X-Frost-Nonce", nonce);
        headers.emplace_back("X-Frost-Timestamp", std::to_string(now));
        if (!token.empty()) headers.emplace_back("Authorization", "Bearer " + token);

        Round r = HttpRoundTrip(base_url, method, path, body, headers, o.timeout_ms);
        auto sigIt = r.headers.find("x-frost-signature");
        if (r.status != 429 || (sigIt != r.headers.end() && !sigIt->second.empty())) {
            VerifyResponse(r, nonce, method, path);
        }
        return r;
    }

    void VerifyResponse(const Round& r, const std::string& nonce, const std::string& method, const std::string& path) {
        std::map<std::string, std::vector<unsigned char>> current;
        {
            std::lock_guard<std::mutex> lk(mtx);
            current = keys;
        }
        if (current.empty()) return;

        auto reject = [&](const std::string& why) {
            throw FrostAuthError("Refusing an unverified answer from the licence server: " + why, Code::Signature, r.status, false);
        };

        auto sigIt = r.headers.find("x-frost-signature");
        auto tsIt = r.headers.find("x-frost-timestamp");
        std::string sig = sigIt != r.headers.end() ? sigIt->second : "";
        std::string ts = tsIt != r.headers.end() ? tsIt->second : "";
        if (sig.empty() || ts.empty()) reject("it was not signed");
        auto nonceIt = r.headers.find("x-frost-nonce");
        if (nonceIt == r.headers.end() || nonceIt->second != nonce) reject("it answered a different request");
        long long tsN = 0;
        try { tsN = std::stoll(ts); } catch (...) { reject("bad timestamp"); }
        if (std::llabs(NowMs() - tsN) > 60'000) reject("it was signed too long ago");

        auto keyIdIt = r.headers.find("x-frost-key-id");
        std::string keyId = keyIdIt != r.headers.end() ? keyIdIt->second : "";
        std::vector<const unsigned char*> candidates;
        for (auto& [id, raw] : current) {
            if (keyId.empty() || id == keyId) candidates.push_back(raw.data());
        }
        if (candidates.empty()) {
            reject("it was signed with key \"" + keyId + "\", which this build does not trust");
        }

        std::string material = ts + "\n" + nonce + "\n" + method + "\n" + path + "\n" + std::to_string(r.status) + "\n" + r.body;
        auto signature = B64uDecode(sig);
        for (auto* key : candidates) {
            if (crypto_sign_verify_detached(signature.data(), reinterpret_cast<const unsigned char*>(material.data()), material.size(), key) == 0) {
                return;
            }
        }
        reject("the signature did not match");
    }

    Json RequestEnvelope(const std::string& method, const std::string& path, const Json* body, const std::string& token) {
        FrostAuthError last("request failed", Code::Network, 0, true);
        for (int attempt = 0; attempt <= o.retries; ++attempt) {
            if (attempt > 0) {
                int cap = std::min(300 * (1 << attempt), 15'000);
                std::this_thread::sleep_for(std::chrono::milliseconds(1 + randombytes_uniform(static_cast<uint32_t>(cap))));
            }
            std::string bodyStr = body ? body->dump() : "";
            Round round;
            try {
                round = OneRound(method, path, bodyStr, token);
            } catch (FrostAuthError& e) {
                if (std::string(e.code) == Code::Signature) throw;
                last = e;
                continue;
            }

            if (round.status == 429) {
                int wait = 2;
                auto raIt = round.headers.find("retry-after");
                if (raIt != round.headers.end()) {
                    try {
                        int parsed = std::stoi(raIt->second);
                        if (parsed > 0 && parsed <= 10) wait = parsed;
                    } catch (...) {   }
                }
                last = FrostAuthError("Rate limited by the licence server", Code::RateLimited, 429, true);
                if (attempt < o.retries) {
                    std::this_thread::sleep_for(std::chrono::seconds(wait));
                    continue;
                }
                throw last;
            }

            Json payload = round.body.empty() ? Json{} : Json::parse_checked(round.body);
            const Json* resp = payload.find("response");

            if (round.status >= 500) {
                std::string typed;
                if (resp) {
                    if (auto* ec = resp->find("errorCode"); ec && ec->is_string()) typed = ec->string;
                }
                if (!typed.empty()) {
                    std::string msg = resp ? resp->str_or("message") : "";
                    if (msg.empty()) msg = "Request failed (" + std::to_string(round.status) + ")";
                    throw FrostAuthError(msg, typed, round.status, false);
                }
                std::string msg = resp ? resp->str_or("message") : "";
                last = FrostAuthError(msg.empty() ? "The licence server is having trouble" : msg, Code::ServerError, round.status, true);
                continue;
            }

            bool hasError = false;
            std::string errCode;
            if (auto* e = payload.find("error"); e) {
                if (e->type == Json::Type::Bool) hasError = e->boolean;
                else if (!e->is_null()) { hasError = true; if (e->is_string()) errCode = e->string; }
            }
            std::string respCode;
            std::string respMsg;
            if (resp) {
                if (auto* ec = resp->find("errorCode"); ec && ec->is_string()) respCode = ec->string;
                respMsg = resp->str_or("message");
            }
            if (hasError || round.status < 200 || round.status > 299) {
                std::string code = !respCode.empty() ? respCode : (!errCode.empty() ? errCode : Code::ServerError);
                std::string msg = !respMsg.empty() ? respMsg : "Request failed (" + std::to_string(round.status) + ")";
                throw FrostAuthError(msg, code, round.status, false);
            }

            Json data;
            if (resp) {
                if (auto* d = resp->find("data"); d) data = *d;
            }
            bool update = false;
            {
                std::lock_guard<std::mutex> lk(mtx);
                AdoptLocked(data);
            }
            (void)update;
            return data;
        }
        throw last;
    }
};

std::shared_ptr<FrostAuthClient> FrostAuthClient::Create(Options o) {
    for (auto [name, v] : {std::pair<const char*, std::string>{"owner", o.owner}, {"product", o.product}, {"version", o.version}}) {
        if (v.empty()) {
            throw FrostAuthError(std::string(name) + " is required", Code::Config, 0, false);
        }
    }
    static bool sodiumReady = false;
    if (!sodiumReady) {
        if (sodium_init() < 0) {
            throw FrostAuthError("libsodium failed to initialise", Code::Config, 0, false);
        }
        sodiumReady = true;
    }
    auto client = std::shared_ptr<FrostAuthClient>(new FrostAuthClient());
    client->impl_ = std::make_unique<Impl>();
    client->impl_->o = std::move(o);
    client->impl_->base_url = client->impl_->o.base_url.empty() ? kDefaultBaseUrl : client->impl_->o.base_url;

    std::string scheme;
    {
        const std::string& u = client->impl_->base_url;
        if (u.rfind("https://", 0) == 0) scheme = "https";
        else if (u.rfind("http://", 0) == 0) scheme = "http";
        std::string host = HostOf(u);
        bool loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
        if (scheme == "http" && !loopback && !client->impl_->o.allow_insecure) {
            throw FrostAuthError(
                "Refusing to send a licence key over plain http. Use https, or pass allow_insecure=true "
                "if you know what you are doing.", Code::Config, 0, false);
        }
    }
    return client;
}

FrostAuthClient::~FrostAuthClient() { Close(); }

Json FrostAuthClient::Init() {
    impl_->AssertRealHost();
    std::string path = std::string("/api/v1/settings/catalog/") + impl_->o.owner + "/" + impl_->o.product;
    auto round = impl_->OneRound("GET", path, "", "");
    Json body = round.body.empty() ? Json{} : Json::parse_checked(round.body);
    if (!body.is_object() || !body.find("success") || body.find("success")->type != Json::Type::Bool
        || !body.find("success")->boolean) {
        std::string code = body.str_or("error");
        if (code.empty()) code = "APP_NOT_FOUND";
        std::string msg = body.str_or("message");
        if (msg.empty()) msg = "Application not found";
        throw FrostAuthError(msg, code, 404, false);
    }
    std::string keyId = body.str_or("key_id");
    std::string served = body.str_or("public_key");
    static const std::map<std::string, std::string> kPublicKeys = {
        {"k2", "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo"},
    };
    auto it = kPublicKeys.find(keyId);
    if (keyId.empty() || it == kPublicKeys.end() || it->second != served) {
        throw FrostAuthError("Server identity check failed — refusing to continue", Code::Signature, 401, false);
    }
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->keys.clear();
        impl_->keys[keyId] = SpkiToRaw(it->second);
        impl_->app = body;
        impl_->initialized = true;
    }
    return Snapshot();
}

Json FrostAuthClient::Activate(const std::string& key, const std::string& build_hash, const std::string& label) {
    impl_->RequireInit();
    if (key.empty()) throw FrostAuthError("licence key is required", Code::Config, 0, false);
    Json body; body.type = Json::Type::Object;
    body.set("key", Json::Str(key));
    body.set("hwid", Json::Str(impl_->MachineId()));
    body.set("os", Json::Str(OsName()));
    body.set("appVersion", Json::Str(impl_->o.version));
    if (impl_->o.collect_hardware) {
        auto [components, virtualized] = HardwareProfile();
        Json comps; comps.type = Json::Type::Array;
        for (auto& [n, v] : components) {
            Json c; c.type = Json::Type::Object;
            c.set("n", Json::Str(n));
            c.set("v", Json::Str(v));
            comps.array.push_back(std::move(c));
        }
        body.set("components", comps);
        body.set("virtual", Json::Bool(virtualized));
    }
    if (!build_hash.empty()) body.set("hash", Json::Str(build_hash));
    if (!label.empty()) body.set("label", Json::Str(Trunc(label, 64)));
    Json data = impl_->RequestEnvelope("POST", "/api/v1/activate", &body, "");
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->stored_key = key;
        impl_->AdoptLocked(data);
        impl_->activated = true;
        impl_->has_offline_since = false;
    }
    if (on_activated) on_activated(Snapshot());
    return Snapshot();
}

Json FrostAuthClient::Register(const std::string& key, const std::string& username, const std::string& password, const std::string& build_hash, const std::string& label) {
    impl_->RequireInit();
    if (key.empty()) throw FrostAuthError("licence key is required", Code::Config, 0, false);
    Json body; body.type = Json::Type::Object;
    body.set("key", Json::Str(key));
    body.set("username", Json::Str(username));
    body.set("password", Json::Str(password));
    body.set("hwid", Json::Str(impl_->MachineId()));
    body.set("os", Json::Str(OsName()));
    body.set("appVersion", Json::Str(impl_->o.version));
    if (impl_->o.collect_hardware) {
        auto [components, virtualized] = HardwareProfile();
        Json comps; comps.type = Json::Type::Array;
        for (auto& [n, v] : components) {
            Json c; c.type = Json::Type::Object;
            c.set("n", Json::Str(n));
            c.set("v", Json::Str(v));
            comps.array.push_back(std::move(c));
        }
        body.set("components", comps);
        body.set("virtual", Json::Bool(virtualized));
    }
    if (!build_hash.empty()) body.set("hash", Json::Str(build_hash));
    if (!label.empty()) body.set("label", Json::Str(Trunc(label, 64)));
    Json data = impl_->RequestEnvelope("POST", "/api/v1/sdk/register", &body, "");
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->stored_key = key;
        impl_->AdoptLocked(data);
        impl_->activated = true;
        impl_->has_offline_since = false;
    }
    if (on_activated) on_activated(Snapshot());
    return Snapshot();
}

Json FrostAuthClient::Login(const std::string& username, const std::string& password, const std::string& twofa, const std::string& build_hash, const std::string& label) {
    impl_->RequireInit();
    Json body; body.type = Json::Type::Object;
    body.set("owner", Json::Str(impl_->o.owner));
    body.set("product", Json::Str(impl_->o.product));
    body.set("username", Json::Str(username));
    body.set("password", Json::Str(password));
    body.set("hwid", Json::Str(impl_->MachineId()));
    body.set("os", Json::Str(OsName()));
    body.set("appVersion", Json::Str(impl_->o.version));
    if (impl_->o.collect_hardware) {
        auto [components, virtualized] = HardwareProfile();
        Json comps; comps.type = Json::Type::Array;
        for (auto& [n, v] : components) {
            Json c; c.type = Json::Type::Object;
            c.set("n", Json::Str(n));
            c.set("v", Json::Str(v));
            comps.array.push_back(std::move(c));
        }
        body.set("components", comps);
        body.set("virtual", Json::Bool(virtualized));
    }
    if (!twofa.empty()) body.set("twofa", Json::Str(twofa));
    if (!build_hash.empty()) body.set("hash", Json::Str(build_hash));
    if (!label.empty()) body.set("label", Json::Str(Trunc(label, 64)));
    Json data = impl_->RequestEnvelope("POST", "/api/v1/sdk/login", &body, "");
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->AdoptLocked(data);
        impl_->activated = true;
        impl_->has_offline_since = false;
    }
    if (on_logged_in) on_logged_in(Snapshot());
    if (on_activated) on_activated(Snapshot());
    return Snapshot();
}

Json FrostAuthClient::Upgrade(const std::string& username, const std::string& password, const std::string& key) {
    impl_->RequireInit();
    Json body; body.type = Json::Type::Object;
    body.set("owner", Json::Str(impl_->o.owner));
    body.set("product", Json::Str(impl_->o.product));
    body.set("username", Json::Str(username));
    body.set("password", Json::Str(password));
    body.set("key", Json::Str(key));
    return impl_->RequestEnvelope("POST", "/api/v1/sdk/upgrade", &body, "");
}

Json FrostAuthClient::Logout() {
    std::string tok;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        tok = impl_->Token();
    }
    Json out;
    try {
        if (tok.empty()) {
            out.type = Json::Type::Object;
            out.set("signedOut", Json::Bool(true));
        } else {
            out = impl_->RequestEnvelope("POST", "/api/v1/sdk/logout", nullptr, tok);
        }
    } catch (...) {
        Close();
        throw;
    }
    Close();
    return out;
}

Json FrostAuthClient::Session() {
    std::string tok;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        tok = impl_->Token();
    }
    if (tok.empty()) {
        throw FrostAuthError("This call needs a session — activate or sign in first", Code::NotActivated, 0, false);
    }
    Json data = impl_->RequestEnvelope("GET", "/api/v1/sdk/session", nullptr, tok);
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->AdoptLocked(data);
    }
    return Snapshot();
}

Json FrostAuthClient::AuthedCall(const std::string& method, const std::string& path, const Json* body) {
    std::string tok;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        tok = impl_->Token();
    }
    if (tok.empty()) {
        throw FrostAuthError("This call needs a session — activate or sign in first", Code::NotActivated, 0, false);
    }
    return impl_->RequestEnvelope(method, path, body, tok);
}

std::string FrostAuthClient::Variable(const std::string& key) {
    Json data = AuthedCall("GET", "/api/v1/sdk/vars/app/" + UrlEscape(key), nullptr);
    return data.str_or("value");
}

Json FrostAuthClient::ListVars() {
    return AuthedCall("GET", "/api/v1/sdk/vars/user", nullptr);
}

Json FrostAuthClient::GetVar(const std::string& key) {
    return AuthedCall("GET", "/api/v1/sdk/vars/user/" + UrlEscape(key), nullptr);
}

Json FrostAuthClient::SetVar(const std::string& key, const std::string& value) {
    Json body; body.type = Json::Type::Object;
    body.set("value", Json::Str(value));
    return AuthedCall("PUT", "/api/v1/sdk/vars/user/" + UrlEscape(key), &body);
}

Json FrostAuthClient::ChangeUsername(const std::string& username, const std::string& password) {
    Json body; body.type = Json::Type::Object;
    body.set("username", Json::Str(username));
    body.set("password", Json::Str(password));
    return AuthedCall("PATCH", "/api/v1/sdk/username", &body);
}

Json FrostAuthClient::Log(const std::string& message) {
    Json body; body.type = Json::Type::Object;
    body.set("message", Json::Str(Trunc(message, 256)));
    return AuthedCall("POST", "/api/v1/sdk/log", &body);
}

Json FrostAuthClient::Ban(const std::string& reason) {
    try {
        Json body; body.type = Json::Type::Object;
        body.set("reason", Json::Str(Trunc(reason, 200)));
        return AuthedCall("POST", "/api/v1/sdk/ban", &body);
    } catch (...) {
        StopHeartbeat();
        std::lock_guard<std::mutex> lk(impl_->mtx);
        impl_->activated = false;
        impl_->assertion.clear();
        impl_->offline_until.clear();
        throw;
    }
    StopHeartbeat();
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->activated = false;
    impl_->assertion.clear();
    impl_->offline_until.clear();
}

Json FrostAuthClient::FetchOnline() { return AuthedCall("GET", "/api/v1/sdk/online", nullptr); }
Json FrostAuthClient::CheckBlacklist() { return AuthedCall("GET", "/api/v1/sdk/checkblacklist", nullptr); }

Json FrostAuthClient::Webhook(const std::string& web_id, const std::string& params, const std::string& body, const std::string& conttype) {
    if (web_id.empty()) throw FrostAuthError("webhook id is required", Code::Config, 0, false);
    Json payload; payload.type = Json::Type::Object;
    if (!params.empty()) payload.set("params", Json::Str(Trunc(params, 2048)));
    if (!body.empty()) payload.set("body", Json::Str(Trunc(body, 8192)));
    if (!conttype.empty()) payload.set("conttype", Json::Str(Trunc(conttype, 128)));
    return AuthedCall("POST", "/api/v1/sdk/webhook/" + UrlEscape(web_id), &payload);
}

Json FrostAuthClient::AppData() { return AuthedCall("GET", "/api/v1/sdk/app", nullptr); }

std::vector<unsigned char> FrostAuthClient::File(const std::string&  ) {
    throw FrostAuthError("File downloads are disabled on this server", Code::ServerError, 0, false);
}

Json FrostAuthClient::Validate() {
    impl_->RequireInit();
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        if (impl_->Token().empty() && impl_->stored_key.empty()) {
            throw FrostAuthError("Activate before validating", Code::NotActivated, 0, false);
        }
    }
    auto SendValidate = [this]() -> Json {
        std::string tok, key;
        {
            std::lock_guard<std::mutex> lk(impl_->mtx);
            tok = impl_->Token();
            key = impl_->stored_key;
        }
        Json payload; payload.type = Json::Type::Object;
        payload.set("hwid", Json::Str(impl_->MachineId()));
        payload.set("appVersion", Json::Str(impl_->o.version));
        payload.set("os", Json::Str(OsName()));
        if (!tok.empty()) payload.set("token", Json::Str(tok));
        else if (!key.empty()) payload.set("key", Json::Str(key));
        else throw FrostAuthError("activate before validating", Code::NotActivated, 0, false);
        return impl_->RequestEnvelope("POST", "/api/v1/validate", &payload, "");
    };
    try {
        Json data = SendValidate();
        {
            std::lock_guard<std::mutex> lk(impl_->mtx);
            impl_->AdoptLocked(data);
            impl_->activated = true;
            impl_->has_offline_since = false;
        }
        if (on_validated) on_validated(Snapshot());
        return Snapshot();
    } catch (FrostAuthError& err) {
        bool stale = err.code == "INVALID_TOKEN" || err.code == "INVALID_SESSION";
        std::string key;
        {
            std::lock_guard<std::mutex> lk(impl_->mtx);
            key = impl_->stored_key;
        }
        if (stale && !key.empty()) {
            {
                std::lock_guard<std::mutex> lk(impl_->mtx);
                impl_->session = Json{};
            }
            Json data = SendValidate();
            {
                std::lock_guard<std::mutex> lk(impl_->mtx);
                impl_->AdoptLocked(data);
                impl_->activated = true;
                impl_->has_offline_since = false;
            }
            if (on_validated) on_validated(Snapshot());
            return Snapshot();
        }
        throw;
    }
}

void FrostAuthClient::StartHeartbeat(int interval_seconds) {
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        if (impl_->Token().empty() && impl_->stored_key.empty()) {
            throw FrostAuthError(
                "Nothing to heartbeat with: activate with a licence key, or sign in on a plan that issues session tokens.", Code::NotActivated, 0, false);
        }
        impl_->closed = false;
    }
    StopHeartbeat();
    impl_->heartbeat_stop = false;
    impl_->heartbeat = std::thread([this, interval_seconds]() {
        int tick = 0;
        while (!impl_->heartbeat_stop.load()) {
            int wait_s = interval_seconds > 0 ? interval_seconds : 180;
            for (int i = 0; i < wait_s * 4 && !impl_->heartbeat_stop.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            if (impl_->heartbeat_stop.load()) return;
            try {
                Validate();
            } catch (FrostAuthError& err) {
                if (err.needs_activation()) {
                    { std::lock_guard<std::mutex> lock(impl_->mtx); impl_->activated = false; }
                    impl_->heartbeat_stop = true;
                    if (on_needs_activation) on_needs_activation(err);
                    return;
                }
                if (err.code == Code::Signature || err.terminal()) {
                    { std::lock_guard<std::mutex> lock(impl_->mtx); impl_->activated = false; }
                    impl_->heartbeat_stop = true;
                    if (on_invalid) on_invalid(err);
                    return;
                }
                long offlineFor = 0;
                bool verified = false;
                bool stop = false;
                {
                    std::lock_guard<std::mutex> lk(impl_->mtx);
                    if (!impl_->has_offline_since) {
                        impl_->offline_since_ms = NowMs();
                        impl_->has_offline_since = true;
                    }
                    offlineFor = (NowMs() - impl_->offline_since_ms) / 1000;
                    std::string a = impl_->assertion;
                    std::string mid = impl_->machine_id;
                    auto pins = impl_->keys;
                    if (!a.empty()) {
                        auto r = VerifyAssertion(a, pins, mid);
                        verified = r.ok;
                    }
                    stop = !verified && (!a.empty() || offlineFor >= impl_->o.offline_grace_seconds);
                    if (stop) impl_->activated = false;
                }
                if (on_offline) on_offline(err, offlineFor, verified);
                if (stop) {
                    impl_->heartbeat_stop = true;
                    if (on_invalid) {
                        on_invalid(FrostAuthError("Could not reach the licence server for " + std::to_string(offlineFor) + "s", Code::Network, 0, true));
                    }
                    return;
                }
            }
            ++tick;
        }
    });
}

void FrostAuthClient::StopHeartbeat() {
    impl_->heartbeat_stop = true;
    if (impl_->heartbeat.joinable()) impl_->heartbeat.join();
}

void FrostAuthClient::Close() {
    if (!impl_) return;
    StopHeartbeat();
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->closed = true;
    impl_->stored_key.clear();
    impl_->session = Json{};
    impl_->activated = false;
    impl_->account = Json{};
    impl_->subscriptions.clear();
    impl_->assertion.clear();
    impl_->offline_until.clear();
    impl_->has_offline_since = false;
}

AssertionResult FrostAuthClient::CheckOffline() {
    std::string a, mid;
    std::map<std::string, std::vector<unsigned char>> pins;
    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        a = impl_->assertion;
        mid = impl_->machine_id;
        pins = impl_->keys;
    }
    if (a.empty()) {
        AssertionResult r;
        r.reason = "no assertion issued yet";
        return r;
    }
    if (pins.empty()) {
        AssertionResult r;
        r.reason = "no pinned publicKey to verify against";
        return r;
    }
    return VerifyAssertion(a, pins, mid);
}

Json FrostAuthClient::Snapshot() const {
    std::lock_guard<std::mutex> lk(impl_->mtx);
    return impl_->SnapshotLocked();
}

}
