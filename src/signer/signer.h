#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace testing
{
	class signer
	{
	  public:
		explicit signer(const std::filesystem::path& directory);
		~signer();
		signer(signer&&) noexcept;
		signer& operator=(signer&&) noexcept;

		std::vector<uint8_t> sign(std::span<const uint8_t> bytecode) const;
		bool verify(std::span<const uint8_t> bytecode) const;
		std::array<uint8_t, 16> solve(const std::array<uint8_t, 12>& target) const;
		std::array<uint8_t, 12> evaluate(const std::array<uint8_t, 16>& signature) const;

	  private:
		class implementation;
		std::unique_ptr<implementation> m_impl;
	};
} 
