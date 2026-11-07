#pragma once
#include <string>
#include <string_view>

std::string http_fingerprint();
std::string http_request(std::string_view payload);
