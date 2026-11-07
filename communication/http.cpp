#include "http.hpp"
#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <utility>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")

std::string http_fingerprint()
    {
        HW_PROFILE_INFOW profile{};
        if (!GetCurrentHwProfileW(&profile))
            return {};

        std::string identity;
        for (wchar_t ch : profile.szHwProfileGuid)
        {
            if (!ch)
                break;
            if (ch != L'{' && ch != L'}' && ch != L'-')
                identity.push_back(static_cast<char>(ch));
        }
        if (identity.empty())
            return {};

        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            return {};

        DWORD object_size = 0;
        DWORD digest_size = 0;
        DWORD received = 0;
        const bool properties_ok = BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received, 0)) &&
            BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&digest_size), sizeof(digest_size), &received, 0));
        if (!properties_ok || !object_size || !digest_size)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }

        std::vector<UCHAR> object(object_size);
        std::vector<UCHAR> digest(digest_size);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0, 0)))
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }

        bool hashed = BCRYPT_SUCCESS(BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(identity.data()), static_cast<ULONG>(identity.size()), 0));
        char computer_name[MAX_COMPUTERNAME_LENGTH + 1]{};
        DWORD name_length = sizeof(computer_name);
        if (hashed && GetComputerNameA(computer_name, &name_length))
            hashed = BCRYPT_SUCCESS(BCryptHashData(hash,
                reinterpret_cast<PUCHAR>(computer_name), name_length, 0));
        DWORD volume_serial = 0;
        if (hashed && GetVolumeInformationA("C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0))
            hashed = BCRYPT_SUCCESS(BCryptHashData(hash,
                reinterpret_cast<PUCHAR>(&volume_serial), sizeof(volume_serial), 0));
        if (hashed)
            hashed = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(), digest_size, 0));
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (!hashed)
            return {};

        constexpr char hex[] = "0123456789abcdef";
        std::string result(digest_size * 2, '0');
        for (size_t i = 0; i < digest.size(); ++i)
        {
            result[i * 2] = hex[digest[i] >> 4];
            result[i * 2 + 1] = hex[digest[i] & 15];
        }
        return result;
    }

namespace
{
    constexpr size_t http_body_limit = 10 * 1024 * 1024;

    bool blocked_http_host(std::wstring host)
    {
        std::transform(host.begin(), host.end(), host.begin(), [](wchar_t ch) {
            return ch >= L'A' && ch <= L'Z' ? ch - L'A' + L'a' : ch;
        });
        while (!host.empty() && host.back() == L'.')
            host.pop_back();
        static constexpr std::wstring_view blocked[] = {
            L"accountinformation.roblox.com", L"accountsettings.roblox.com", L"twostepverification.roblox.com",
            L"trades.roblox.com", L"billing.roblox.com", L"economy.roblox.com",
            L"auth.roblox.com", L"accountinformation.roproxy.com", L"accountsettings.roproxy.com",
            L"twostepverification.roproxy.com", L"trades.roproxy.com", L"billing.roproxy.com",
            L"economy.roproxy.com", L"auth.roproxy.com", L"api.ipify.org",
            L"api4.ipify.org", L"api6.ipify.org", L"api64.ipify.org",
            L"api.ipapi.is", L"api.ipapi.co", L"api.ipapi.com",
            L"api.ipinfo.io", L"api.ipgeolocation.io", L"api.freegeoip.app",
            L"api.myip.com", L"api.ip.sb", L"api.ipwhois.io",
            L"api.ipdata.co", L"api.ipstack.com", L"api.db-ip.com",
            L"api.seeip.org", L"api.ipregistry.co", L"api.abstractapi.com",
            L"api.ipbase.com", L"api.iplocation.net", L"api.ip.nf",
            L"api.bigdatacloud.net", L"api.techniknews.net", L"api.country.is",
            L"api.2ip.me", L"api.reallyfreegeoip.org",
        };
        for (std::wstring_view domain : blocked)
        {
            if (host == domain || (host.size() > domain.size() &&
                host.ends_with(domain) && host[host.size() - domain.size() - 1] == L'.'))
                return true;
        }
        return false;
    }

    struct internet_handle
    {
        HINTERNET value;
        explicit internet_handle(HINTERNET handle) : value(handle)
        {
            if (!value)
                throw std::runtime_error("request: Windows HTTP error " + std::to_string(GetLastError()));
        }
        ~internet_handle() { WinHttpCloseHandle(value); }
        internet_handle(const internet_handle&) = delete;
        internet_handle& operator=(const internet_handle&) = delete;
    };

    void check_http(BOOL ok)
    {
        if (!ok)
            throw std::runtime_error("request: Windows HTTP error " + std::to_string(GetLastError()));
    }

    std::wstring wide_http(std::string_view text)
    {
        if (text.empty()) return {};
        const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (!size) throw std::runtime_error("request: invalid UTF-8 metadata");
        std::wstring result(size, L'\0');
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size))
            throw std::runtime_error("request: invalid UTF-8 metadata");
        return result;
    }

    std::string narrow_http(std::wstring_view text)
    {
        if (text.empty()) return {};
        const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (!size) throw std::runtime_error("request: invalid response metadata");
        std::string result(size, '\0');
        if (!WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size, nullptr, nullptr))
            throw std::runtime_error("request: invalid response metadata");
        return result;
    }

    std::string_view read_http_field(std::string_view& data, size_t limit)
    {
        const size_t end = data.find('\n');
        if (end == std::string_view::npos || end == 0 || end > 10)
            throw std::runtime_error("request: invalid bridge field length");
        size_t size = 0;
        const auto parsed = std::from_chars(data.data(), data.data() + end, size);
        if (parsed.ec != std::errc{} || parsed.ptr != data.data() + end || size > limit || size > data.size() - end - 1)
            throw std::runtime_error("request: invalid bridge field");
        data.remove_prefix(end + 1);
        const auto field = data.substr(0, size);
        data.remove_prefix(size);
        return field;
    }

    void append_http_field(std::string& output, std::string_view field)
    {
        output += std::to_string(field.size());
        output += '\n';
        output.append(field);
    }

    bool header_is(std::string_view value, std::string_view expected)
    {
        return value.size() == expected.size() && std::equal(value.begin(), value.end(), expected.begin(), [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); });
    }

    std::wstring query_http_text(HINTERNET request, DWORD query)
    {
        DWORD bytes = 0;
        if (!WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &bytes, WINHTTP_NO_HEADER_INDEX) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            check_http(FALSE);
        if (bytes > 128 * 1024) throw std::runtime_error("request: response headers too large");
        std::wstring result(bytes / sizeof(wchar_t), L'\0');
        check_http(WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, result.data(), &bytes, WINHTTP_NO_HEADER_INDEX));
        result.resize(bytes / sizeof(wchar_t));
        while (!result.empty() && result.back() == L'\0') result.pop_back();
        return result;
    }
}

std::string http_request(std::string_view payload)
{
    const auto url_text = read_http_field(payload, 4096);
    const auto method_text = read_http_field(payload, 32);
    const auto count_text = read_http_field(payload, 3);
    unsigned count = 0;
    const auto parsed = std::from_chars(count_text.data(), count_text.data() + count_text.size(), count);
    if (parsed.ec != std::errc{} || parsed.ptr != count_text.data() + count_text.size() || count > 128)
        throw std::runtime_error("request: invalid header count");
    if (method_text.empty() || !std::all_of(method_text.begin(), method_text.end(), [](unsigned char c) { return c >= 'A' && c <= 'Z'; }))
        throw std::runtime_error("request: invalid HTTP method");

    std::wstring headers = L"Exploit-Identifier: Tea\r\n";
    for (unsigned i = 0; i < count; ++i)
    {
        const auto name = read_http_field(payload, 256);
        const auto value = read_http_field(payload, 16384);
        constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
        if (name.empty() || !std::all_of(name.begin(), name.end(), [punctuation](unsigned char c)
            { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || punctuation.find(c) != std::string_view::npos; }) || value.find_first_of("\r\n") != std::string_view::npos || value.find('\0') != std::string_view::npos)
            throw std::runtime_error("request: invalid header");
        if (header_is(name, "User-Agent") || header_is(name, "Exploit-Identifier")) continue;
        if (header_is(name, "Host") || header_is(name, "Content-Length") || header_is(name, "Transfer-Encoding") || header_is(name, "Connection"))
            throw std::runtime_error("request: transport-managed header");
        headers += wide_http(name) + L": " + wide_http(value) + L"\r\n";
        if (headers.size() > 32768) throw std::runtime_error("request: headers too large");
    }
    const auto body = read_http_field(payload, http_body_limit);
    if (!payload.empty()) throw std::runtime_error("request: trailing bridge data");
    if (url_text.find_first_of("\r\n") != std::string_view::npos || url_text.find('\0') != std::string_view::npos)
        throw std::runtime_error("request: invalid URL");

    const auto url = wide_http(url_text);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength =
        parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
    check_http(WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts));
    if ((parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS) || !parts.dwHostNameLength || parts.dwUserNameLength || parts.dwPasswordLength)
        throw std::runtime_error("request: expected HTTP(S) URL without credentials");
    const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    if (blocked_http_host(host))
        throw std::runtime_error("request: url is blocked");
    std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
    if (path.empty()) path = L"/";
    if (parts.dwExtraInfoLength) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    if (const size_t fragment = path.find(L'#'); fragment != std::wstring::npos) path.resize(fragment);
    const auto method = wide_http(method_text);

    internet_handle session(WinHttpOpen(L"Tea", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    check_http(WinHttpSetTimeouts(session.value, 15000, 15000, 30000, 30000));
    internet_handle connection(WinHttpConnect(session.value, host.c_str(), parts.nPort, 0));
    internet_handle request(WinHttpOpenRequest(connection.value, method.c_str(), path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0));
    DWORD disabled_features = WINHTTP_DISABLE_REDIRECTS;
    check_http(WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled_features, sizeof(disabled_features)));
    check_http(WinHttpAddRequestHeaders(request.value, L"User-Agent: Tea", static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE));
    DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    check_http(WinHttpSetOption(request.value, WINHTTP_OPTION_DECOMPRESSION, &decompression, sizeof(decompression)));
    check_http(WinHttpSendRequest(request.value, headers.c_str(), static_cast<DWORD>(headers.size()), body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0));
    check_http(WinHttpReceiveResponse(request.value, nullptr));
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    check_http(WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX));
    const auto reason = narrow_http(query_http_text(request.value, WINHTTP_QUERY_STATUS_TEXT));
    const auto raw_headers = query_http_text(request.value, WINHTTP_QUERY_RAW_HEADERS_CRLF);
    std::vector<std::pair<std::string, std::string>> response_headers;
    size_t begin = raw_headers.find(L"\r\n");
    if (begin != std::wstring::npos) begin += 2;
    while (begin != std::wstring::npos && begin < raw_headers.size())
    {
        const size_t end = raw_headers.find(L"\r\n", begin);
        if (end == std::wstring::npos || end == begin) break;
        const size_t colon = raw_headers.find(L':', begin);
        if (colon != std::wstring::npos && colon < end)
        {
            size_t value_begin = colon + 1;
            while (value_begin < end && (raw_headers[value_begin] == L' ' || raw_headers[value_begin] == L'\t')) ++value_begin;
            response_headers.emplace_back(narrow_http(std::wstring_view(raw_headers).substr(begin, colon - begin)),
                narrow_http(std::wstring_view(raw_headers).substr(value_begin, end - value_begin)));
        }
        begin = end + 2;
    }
    std::string response_body;
    std::array<char, 16384> buffer{};
    const ULONGLONG deadline = GetTickCount64() + 90000;
    for (;;)
    {
        if (GetTickCount64() > deadline) throw std::runtime_error("request: response timed out");
        DWORD received = 0;
        check_http(WinHttpReadData(request.value, buffer.data(), static_cast<DWORD>(buffer.size()), &received));
        if (!received) break;
        if (received > http_body_limit - response_body.size()) throw std::runtime_error("request: response exceeds 10mb");
        response_body.append(buffer.data(), received);
    }
    std::string output;
    append_http_field(output, std::to_string(status));
    append_http_field(output, reason);
    append_http_field(output, std::to_string(response_headers.size()));
    for (const auto& [name, value] : response_headers)
    {
        append_http_field(output, name);
        append_http_field(output, value);
    }
    append_http_field(output, response_body);
    return output;
}
