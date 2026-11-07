#include <src/globals.h>
#include <src/roblox/offsets.h>
#include <src/memory/memory.h>
#include <src/process/process.h>
#include <src/injector/injector.h>
#include <src/functions/functions.h>
#include <src/execution/execution.h>
#include <src/hooks/hooks.h>
#include <src/signer/signer_api.h>
#include <communication/communication.hpp>
#include <communication/http.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>

// yes everything tea and don't change it

int main()
{
    if (!injector->initialize()) {
        std::cout << "[-] initialize failed\n";
        system("pause");
        return 1;
    }

    char exe_path[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, exe_path, MAX_PATH)) {
        std::cerr << "[-] could not locate the exe\n";
        return 1;
    }
    const auto exe_dir = std::filesystem::path(exe_path).parent_path();
    if (!signer->initialize(exe_dir / "tables"))
        printf("[!] bytecode signer init failed: %s\n", signer->last_error().c_str());

    std::ifstream env_file(exe_dir / "env.luau", std::ios::binary);
    if (!env_file) {
        std::cerr << "[-] could not open env.luau\n";
        return 1;
    }
    const std::string env_script((std::istreambuf_iterator<char>(env_file)), std::istreambuf_iterator<char>());
    if (env_file.bad() || env_script.empty()) {
        std::cerr << "[-] could not read env.luau\n";
        return 1;
    }

    const std::string http_token = communication->generate_token();
    const std::string http_device = http_fingerprint();
    if (http_token.empty() || http_device.empty()) {
        std::cerr << "[-] could not initialize http bridge\n";
        return 1;
    }
    const std::string bootstrap = "local tea_http_token = \"" + http_token +
        "\"\nlocal tea_http_fingerprint = \"" + http_device + "\"\n" + env_script;

    if (!communication->initialize(http_token)) {
        std::cerr << "[-] communication failed to start (something might be holding port 6969)\n";
        system("pause");
        return 1;
    }

    uintptr_t fake = 0;
    uintptr_t children = 0;
    uintptr_t first_child = 0;
    if (!read_value(rebase(offsets::data_model::fake_data_model), fake) || !read_value(fake + offsets::data_model::real_data_model, globals::data_model) || !read_value(globals::data_model + offsets::data_model::children, children) || !read_value(children, first_child) || !read_value(first_child + offsets::data_model::script_context, globals::script_context) || !execution->initialize() || !execution->execute(bootstrap, "@Tea", false)) {
        std::cerr << "[-] could not initialize Tea environment\n";
        communication->shutdown();
        return 1;
    }
    session_ready.store(true);
    printf("[+] initialized\n");

    system("pause");
    session_ready.store(false);
    communication->shutdown();
    return 0;
}

