#include "signer.h"
#include "solver.h"
#include <src/roblox/offsets.h>
#include <algorithm>
#include <dependencies/blake3/blake3.h>
#include <stdexcept>

namespace testing
{
	namespace
	{
		detail::bits read_bits(std::span<const uint8_t> bytes)
		{
			detail::bits value;
			for (size_t index = 0; index < bytes.size(); ++index)
				(index < 8 ? value.low : value.high) |= uint64_t(bytes[index]) << ((index & 7) * 8);
			return value;
		}

		template <size_t size> std::array<uint8_t, size> write_bits(detail::bits value)
		{
			std::array<uint8_t, size> bytes{};
			for (size_t index = 0; index < size; ++index)
				bytes[index] = uint8_t((index < 8 ? value.low : value.high) >> ((index & 7) * 8));
			return bytes;
		}

		std::array<uint8_t, 12> digest(std::span<const uint8_t> bytes)
		{
			blake3_hasher state;
			blake3_hasher_init(&state);
			blake3_hasher_update(&state, bytes.data(), bytes.size());
			std::array<uint8_t, 32> hash{};
			blake3_hasher_finalize(&state, hash.data(), hash.size());
			std::array<uint8_t, 12> result{};
			std::copy_n(hash.begin() + 4, result.size(), result.begin());
			return result;
		}
	}

	class signer::implementation
	{
	  public:
		explicit implementation(const std::filesystem::path& directory) : model(directory)
		{
		}

		detail::solver model;
	};

	signer::signer(const std::filesystem::path& directory) : m_impl(std::make_unique<implementation>(directory))
	{
	}

	signer::~signer() = default;
	signer::signer(signer&&) noexcept = default;
	signer& signer::operator=(signer&&) noexcept = default;

	std::array<uint8_t, 16> signer::solve(const std::array<uint8_t, 12>& target) const
	{
		return write_bits<16>(m_impl->model.solve(read_bits(target)));
	}

	std::array<uint8_t, 12> signer::evaluate(const std::array<uint8_t, 16>& signature) const
	{
		return write_bits<12>(m_impl->model.evaluate(read_bits(signature)));
	}

	std::vector<uint8_t> signer::sign(std::span<const uint8_t> bytecode) const
	{
		if (bytecode.empty() || !bytecode.front() || bytecode.size() > offsets::signer::maximum_payload)
			throw std::invalid_argument("expected nonempty compiled bytecode within the size limit");

		std::vector<uint8_t> result(bytecode.begin(), bytecode.end());
		result.resize((std::max)(result.size(), offsets::signer::minimum_payload), 0);
		const auto signature = solve(digest(result));
		result.insert(result.end(), signature.begin(), signature.end());
		for (int index = 0; index < 4; ++index)
			result.push_back(signature[index] ^ uint8_t(offsets::signer::key_value >> (index * 8)));
		for (int index = 0; index < 4; ++index)
			result.push_back(signature[index] ^ offsets::signer::marker[index]);
		if (!verify(result))
			throw std::runtime_error("signed bytecode failed local verification");
		return result;
	}

	bool signer::verify(std::span<const uint8_t> bytecode) const
	{
		if (bytecode.size() < offsets::signer::minimum_payload + offsets::signer::trailer_size ||
			bytecode.size() > offsets::signer::maximum_payload + offsets::signer::trailer_size || !bytecode.front())
			return false;

		const auto trailer = bytecode.last(offsets::signer::trailer_size);
		for (int index = 0; index < 4; ++index)
		{
			if (uint8_t(trailer[16 + index] ^ trailer[index]) != uint8_t(offsets::signer::key_value >> (index * 8)) ||
				uint8_t(trailer[20 + index] ^ trailer[index]) != offsets::signer::marker[index])
				return false;
		}

		std::array<uint8_t, 16> signature{};
		std::copy_n(trailer.begin(), signature.size(), signature.begin());
		return evaluate(signature) == digest(bytecode.first(bytecode.size() - offsets::signer::trailer_size));
	}
} 
