#include <WinSock2.h>
#include <WS2tcpip.h>

#include <communication/communication.hpp>
#include <communication/http.hpp>
#include <communication/misc.hpp>
#include <exception>
#include <src/execution/execution.h>

#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <cstdio>
#include <cstdlib>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Bcrypt.lib")

namespace
{
	constexpr unsigned short port = 6969;
	constexpr uint32_t maximum_script_size = 10 * 1024 * 1024;
	std::atomic<bool> running = false;
	std::thread server_thread;
	std::string load_token;

	std::string lua_literal(const std::string& bytes)
	{
		std::string result;
		result.reserve(bytes.size() + 2);
		result.push_back('"');
		for (const unsigned char byte : bytes)
		{
			if (byte >= 32 && byte <= 126 && byte != '"' && byte != '\\')
			{
				result.push_back(static_cast<char>(byte));
				continue;
			}
			result.push_back('\\');
			result.push_back(static_cast<char>('0' + byte / 100));
			result.push_back(static_cast<char>('0' + (byte / 10) % 10));
			result.push_back(static_cast<char>('0' + byte % 10));
		}
		result.push_back('"');
		return result;
	}

	int hex_digit(char digit)
	{
		if (digit >= '0' && digit <= '9') return digit - '0';
		if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
		if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
		return -1;
	}

	bool decode_hex(const std::string& encoded, std::string& decoded, bool allow_empty = false)
	{
		if ((!allow_empty && encoded.empty()) || encoded.size() > 8192 || encoded.size() % 2 != 0)
			return false;
		decoded.reserve(encoded.size() / 2);
		for (size_t i = 0; i < encoded.size(); i += 2)
		{
			const int high = hex_digit(encoded[i]);
			const int low = hex_digit(encoded[i + 1]);
			if (high < 0 || low < 0)
				return false;
			decoded.push_back(static_cast<char>((high << 4) | low));
		}
		return true;
	}

	bool send_http(SOCKET client, int status, std::string_view body)
	{
		const char* reason = status == 200 ? "OK" : status == 401 ? "Unauthorized" :
			status == 413 ? "Payload Too Large" : status == 500 ? "Internal Server Error" :
            status == 502 ? "Bad Gateway" : "Bad Request";
		const std::string headers = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
		const auto send_all = [client](std::string_view bytes)
		{
			while (!bytes.empty())
			{
				const int sent = send(client, bytes.data(), static_cast<int>((std::min)(bytes.size(), size_t{16384})), 0);
				if (sent <= 0) return false;
				bytes.remove_prefix(sent);
			}
			return true;
		};
		return send_all(headers) && send_all(body);
	}

	void handle_http(SOCKET client)
	{
		std::string data = "POST";
		std::array<char, 16384> chunk{};
		size_t end = std::string::npos;
		while ((end = data.find("\r\n\r\n")) == std::string::npos)
		{
			if (data.size() > 8192) { send_http(client, 400, "HTTP header too large"); return; }
			const int received = recv(client, chunk.data(), static_cast<int>(chunk.size()), 0);
			if (received <= 0) return;
			data.append(chunk.data(), received);
		}
		if (end > 8192) { send_http(client, 400, "HTTP header too large"); return; }
		const size_t line_end = data.find("\r\n");
		const std::string_view line(data.data(), line_end);
        const bool external_http = line.starts_with("POST /http/");
        const bool external_misc = line.starts_with("POST /misc/");
        const std::string_view prefix = external_http ? "POST /http/" :
            external_misc ? "POST /misc/" : "POST /load/";
        constexpr std::string_view suffix = " HTTP/1.1";
        if (!line.starts_with(prefix) || !line.ends_with(suffix))
        {
            send_http(client, 400, "Invalid bridge request");
            return;
        }
        const std::string_view route = line.substr(prefix.size(), line.size() - prefix.size() - suffix.size());
        std::string id;
        std::string chunkname;
        std::string operation;
        if (external_http)
        {
            if (route != load_token)
            {
                send_http(client, 401, "Invalid HTTP token");
                return;
            }
        }
        else if (external_misc)
        {
            const size_t separator = route.find('/');
            if (separator == std::string_view::npos || route.substr(0, separator) != load_token ||
                route.find('/', separator + 1) != std::string_view::npos)
            {
                send_http(client, 401, "Invalid misc token");
                return;
            }
            operation = route.substr(separator + 1);
        }
        else
        {
            const size_t a = route.find('/');
            const size_t b = route.find('/', a == std::string_view::npos ? 0 : a + 1);
            if (a == std::string_view::npos || b == std::string_view::npos ||
                route.find('/', b + 1) != std::string_view::npos || route.substr(0, a) != load_token)
            {
                send_http(client, 401, "Invalid load token");
                return;
            }
            id = route.substr(a + 1, b - a - 1);
            if (id.size() != 36 || !std::all_of(id.begin(), id.end(), [](unsigned char ch)
                { return std::isxdigit(ch) != 0 || ch == '-'; }) ||
                !decode_hex(std::string(route.substr(b + 1)), chunkname, true) ||
                chunkname.size() > 256 || chunkname.find('\0') != std::string::npos)
            {
                send_http(client, 400, "Invalid load metadata");
                return;
            }
        }
		std::string headers = data.substr(0, end + 4);
		std::transform(headers.begin(), headers.end(), headers.begin(),
			[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
		constexpr std::string_view marker = "\r\ncontent-length:";
		const size_t pos = headers.find(marker);
		if (pos == std::string::npos)
		{
			send_http(client, 400, "Missing content length");
			return;
		}
		size_t begin = pos + marker.size();
		while (begin < headers.size() && headers[begin] == ' ') ++begin;
		const size_t finish = headers.find("\r\n", begin);
		size_t length = 0;
		const auto parsed = std::from_chars(headers.data() + begin, headers.data() + finish, length);
		if (parsed.ec != std::errc{} || parsed.ptr != headers.data() + finish)
		{
			send_http(client, 400, "Invalid content length");
			return;
		}
        if (length > maximum_script_size + ((external_http || external_misc) ? 65536 : 0))
		{
			send_http(client, 413, "bridge: payload too large");
			return;
		}
		std::string source = data.substr(end + 4, length);
		source.reserve(length);
		if (headers.find("\r\nexpect: 100-continue\r\n") != std::string::npos)
			send(client, "HTTP/1.1 100 Continue\r\n\r\n", 25, 0);
		while (source.size() < length)
		{
			const int received = recv(client, chunk.data(),
				static_cast<int>((std::min)(chunk.size(), length - source.size())), 0);
			if (received <= 0) return;
			source.append(chunk.data(), received);
		}
        if (external_http)
        {
            try
            {
                const auto response = http_request(source);
                send_http(client, 200, response);
            }
            catch (const std::exception& error)
            {
                send_http(client, 502, error.what());
            }
            return;
        }
        if (external_misc)
        {
            try
            {
                send_http(client, 200, misc_request(operation, source));
            }
            catch (const std::exception& error)
            {
                send_http(client, 502, error.what());
            }
            return;
        }
		const std::string checked = Luau::compile(source);
		if (checked.empty() || checked.front() == '\0')
		{
			send_http(client, 400, chunkname +
				(checked.empty() ? ": compiler returned no bytecode" : checked.substr(1)));
			return;
		}
		const std::string key = lua_literal(id);
		const std::string wrapper = "if tea.__load_pending[" + key + "] ~= nil then tea.__load_pending[" + key + "] = {fn=function(...)\n" + source + "\nend} end";
		bool delivered = false;
		{
			std::lock_guard lock(execution_mutex);
			if (session_ready.load())
				delivered = execution->execute(wrapper, chunkname);
		}
		send_http(client, delivered ? 200 : 500, delivered ? "ok" : "loadstring: could not load compiled function");
	}

	bool read_exact_socket(SOCKET socket, void* buffer, size_t size)
	{
		size_t total = 0;
		auto* output = static_cast<char*>(buffer);
		while (total < size)
		{
			const int received = recv(socket, output + total, static_cast<int>(size - total), 0);
			if (received <= 0)
				return false;
			total += static_cast<size_t>(received);
		}
		return true;
	}

	void serve(std::promise<bool> ready)
	{
		WSADATA wsa{};
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		{
			ready.set_value(false);
			return;
		}

		SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener == INVALID_SOCKET)
		{
			ready.set_value(false);
			WSACleanup();
			return;
		}

		BOOL exclusive = TRUE;
		sockaddr_in address{};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR ||
			bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
			listen(listener, SOMAXCONN) == SOCKET_ERROR)
		{
			std::printf("[-] communication port %u unavailable (wsa %d)\n", port, WSAGetLastError());
			ready.set_value(false);
			closesocket(listener);
			WSACleanup();
			return;
		}

		ready.set_value(true);
		while (running)
		{
			fd_set readable;
			FD_ZERO(&readable);
			FD_SET(listener, &readable);
			timeval timeout{0, 200000};
			const int selected = select(0, &readable, nullptr, nullptr, &timeout);
			if (selected == 0)
				continue;
			if (selected == SOCKET_ERROR)
				break;

			SOCKET client = accept(listener, nullptr, nullptr);
			if (client == INVALID_SOCKET)
				continue;

			const int receive_timeout_ms = 1000;
			setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&receive_timeout_ms), sizeof(receive_timeout_ms));

			std::array<char, 4> first{};
			if (read_exact_socket(client, first.data(), first.size()))
			{
				if (std::memcmp(first.data(), "POST", first.size()) == 0)
				{
					const int http_timeout_ms = 15000;
					setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
						reinterpret_cast<const char*>(&http_timeout_ms), sizeof(http_timeout_ms));
					handle_http(client);
				}
				else
				{
				uint32_t network_length = 0;
				std::memcpy(&network_length, first.data(), sizeof(network_length));
				const uint32_t length = ntohl(network_length);
				if (length > 0 && length <= maximum_script_size)
				{
					std::string script(length, '\0');
					if (read_exact_socket(client, script.data(), script.size()))
					{
						std::lock_guard lock(execution_mutex);
						if (session_ready.load())
							execution->execute(script);
					}
				}
				}
			}
			closesocket(client);
		}

		closesocket(listener);
		WSACleanup();
	}
}

std::string _communication::generate_token()
{
	std::array<unsigned char, 16> bytes{};
	if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
		return {};
	constexpr char digits[] = "0123456789abcdef";
	std::string token;
	token.reserve(bytes.size() * 2);
	for (const unsigned char byte : bytes)
	{
		token.push_back(digits[byte >> 4]);
		token.push_back(digits[byte & 15]);
	}
	return token;
}

bool _communication::initialize(const std::string& token)
{
	if (token.empty() || server_thread.joinable())
		return false;
	load_token = token;
	running = true;
	std::promise<bool> ready;
	auto result = ready.get_future();
	server_thread = std::thread(serve, std::move(ready));
	if (result.get())
	{
		return true;
	}
	running = false;
	server_thread.join();
	return false;
}

void _communication::shutdown()
{
	running = false;
	if (server_thread.joinable())
		server_thread.join();
}
