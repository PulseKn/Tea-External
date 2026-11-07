#pragma once

#include <string>
#include <atomic>
#include <mutex>

inline std::mutex execution_mutex;
inline std::atomic_bool session_ready{false};

class _communication
{
public:
    static std::string generate_token();
    bool initialize(const std::string& token);
    void shutdown();
};

inline _communication* communication = new _communication();
