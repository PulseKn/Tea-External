#include "signer_api.h"
#include "signer.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace
{
	std::mutex g_mutex;
	std::unique_ptr<testing::signer> g_signer;
}

bool bytecode_signer::initialize(const std::filesystem::path& tables_dir)
{
	std::lock_guard lock(g_mutex);
	try
	{
		g_signer = std::make_unique<testing::signer>(tables_dir);
		m_impl = g_signer.get();
		m_ready = true;
		m_last_error.clear();
		return true;
	}
	catch (const std::exception& e)
	{
		g_signer.reset();
		m_impl = nullptr;
		m_ready = false;
		m_last_error = e.what();
		return false;
	}
}

bool bytecode_signer::is_ready() const
{
	return m_ready;
}

std::string bytecode_signer::last_error() const
{
	return m_last_error;
}

std::vector<uint8_t> bytecode_signer::sign_bytecode(const std::string& compiled_bytecode)
{
	std::lock_guard lock(g_mutex);
	if (!m_ready || !g_signer)
	{
		m_last_error = "signer not initialized";
		return {};
	}
	try
	{
		auto signed_data = g_signer->sign(
			std::span(reinterpret_cast<const uint8_t*>(compiled_bytecode.data()), compiled_bytecode.size()));

		std::vector<uint8_t> result(signed_data.begin(), signed_data.end());
		m_last_error.clear();
		return result;
	}
	catch (const std::exception& e)
	{
		m_last_error = e.what();
		return {};
	}
}

bool bytecode_signer::verify_signed(const std::vector<uint8_t>& signed_bytecode)
{
	if (!m_ready || !g_signer)
		return false;
	return g_signer->verify(std::span(signed_bytecode));
}
