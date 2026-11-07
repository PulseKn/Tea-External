#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

// wraps the bytecode signer for the executor's compile->sign->load pipeline.
// initialize once at startup with the tables directory, then call sign_bytecode
// on compiled luau bytecode before feeding it to the client loader.

class bytecode_signer
{
public:
	// load the 4 signature tables from the directory. call once at startup.
	// returns true on success. tables must match the target client build.
	bool initialize(const std::filesystem::path& tables_dir);

	// sign compiled bytecode: pads to minimum, computes the blake3 digest,
	// solves the trailer, appends it. returns empty vector on failure.
	std::vector<uint8_t> sign_bytecode(const std::string& compiled_bytecode);

	// verify locally that the signed bytecode passes the solver's consistency check.
	bool verify_signed(const std::vector<uint8_t>& signed_bytecode);

	// check whether the signer is initialized and ready.
	bool is_ready() const;

	// get the last error message (empty if none).
	std::string last_error() const;

private:
	void* m_impl = nullptr;
	std::string m_last_error;
	bool m_ready = false;
};

inline bytecode_signer* signer = new bytecode_signer();
