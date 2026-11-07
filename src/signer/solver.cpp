#include "solver.h"
#include <fstream>
#include <random>
#include <stdexcept>

namespace testing::detail
{
	namespace
	{
		std::vector<bits> read_table(const std::filesystem::path& path, size_t count)
		{
			std::ifstream file(path, std::ios::binary | std::ios::ate);
			if (!file || file.tellg() != static_cast<std::streamoff>(count * 16))
				throw std::runtime_error("invalid table: " + path.string());

			file.seekg(0);
			std::vector<bits> result(count);
			for (bits& value : result)
			{
				std::array<uint8_t, 16> bytes{};
				if (!file.read(reinterpret_cast<char*>(bytes.data()), bytes.size()))
					throw std::runtime_error("truncated table: " + path.string());

				for (int index = 0; index < 8; ++index)
					value.low |= uint64_t(bytes[index]) << (index * 8);
				for (int index = 0; index < 4; ++index)
					value.high |= uint64_t(bytes[index + 8]) << (index * 8);
			}
			return result;
		}

		int pair_index(int left, int right)
		{
			return left + 15 * right - right * (right + 1) / 2 - 1;
		}
	} 

	solver::solver(const std::filesystem::path& directory) : m_constant(read_table(directory / "signature-constant.bin", 1).front()), m_linear_a(read_table(directory / "signature-linear-a.bin", 4096)), m_linear_b(read_table(directory / "signature-linear-b.bin", 4096)), m_table(read_table(directory / "signature-quadratic.bin", 245760)), m_quadratic(128 * 128)
	{
		for (int left = 0; left < 128; ++left)
		{
			m_linear[left] = byte_term(left / 8, uint8_t(1 << (left % 8)));
			for (int right = 0; right < left; ++right)
			{
				bits coefficient;
				if (left / 8 == right / 8)
					coefficient = byte_term(left / 8, uint8_t((1 << (left % 8)) | (1 << (right % 8)))) ^
								  m_linear[left] ^ m_linear[right];
				else
					coefficient =
						m_table[(pair_index(left / 8, right / 8) * 8 + 7 - left % 8) * 256 + (1 << (right % 8))];

				m_quadratic[left * 128 + right] = coefficient;
				m_quadratic[right * 128 + left] = coefficient;
			}
		}

		std::mt19937_64 random(0xa17e);
		for (int index = 0; index < 64; ++index)
		{
			const bits value{random(), random()};
			if (evaluate(value) != polynomial(value))
				throw std::runtime_error("tables do not match the quadratic model");
		}
		prepare();
	}

	bits solver::byte_term(int index, uint8_t value) const
	{
		return value ? m_linear_a[index * 256 + value] ^ m_linear_b[index * 256 + value] : bits{};
	}

	bits solver::evaluate(bits value) const
	{
		std::array<uint8_t, 16> bytes{};
		for (int index = 0; index < 16; ++index)
			bytes[index] = uint8_t((index < 8 ? value.low : value.high) >> ((index & 7) * 8));

		bits result = m_constant;
		for (int left = 0; left < 16; ++left)
		{
			result ^= byte_term(left, bytes[left]);
			for (int right = 0; right < left; ++right)
			{
				if (!bytes[right])
					continue;
				for (int bit = 0; bit < 8; ++bit)
				{
					if (bytes[left] & (128 >> bit))
						result ^= m_table[(pair_index(left, right) * 8 + bit) * 256 + bytes[right]];
				}
			}
		}
		return result;
	}

	bits solver::polynomial(bits value) const
	{
		bits result = m_constant;
		for (int left = 0; left < 128; ++left)
		{
			if (!value.test(left))
				continue;
			result ^= m_linear[left];
			for (int right = 0; right < left; ++right)
			{
				if (value.test(right))
					result ^= m_quadratic[left * 128 + right];
			}
		}
		return result;
	}

	void solver::prepare()
	{
		basis images;
		for (int step = 0; step < 16 && images.count < 96; ++step)
		{
			std::vector<bits> projected(m_quadratic.size());
			for (size_t index = 0; index < projected.size(); ++index)
				projected[index] = images.reduce(m_quadratic[index]);

			basis equations;
			for (int output = 0; output < 96; ++output)
			{
				for (int left = 0; left < 128; ++left)
				{
					bits row;
					for (int right = 0; right < 128; ++right)
					{
						if (projected[left * 128 + right].test(output))
							row.set(right);
					}
					equations.insert(row);
				}
			}

			const auto kernel = equations.kernel();
			basis expanded = images;
			layer current;
			current.previous = images;
			for (bits direction : kernel)
			{
				bits image = polynomial(direction) ^ m_constant;
				expanded.insert(image);
				image = images.reduce(image);
				while (!image.empty())
				{
					const int pivot = image.top();
					if (current.images[pivot].empty())
					{
						current.images[pivot] = image;
						current.directions[pivot] = direction;
						break;
					}
					image ^= current.images[pivot];
					direction ^= current.directions[pivot];
				}
			}

			if (expanded.count <= images.count)
				throw std::runtime_error("table structure does not admit the expected inversion");
			m_layers.push_back(std::move(current));
			images = expanded;
		}
		if (images.count != 96)
			throw std::runtime_error("incomplete signature image");
	}

	bits solver::solve(bits target) const
	{
		if (target.high >> 32)
			throw std::invalid_argument("target exceeds 96 bits");
		bits value;
		for (auto it = m_layers.rbegin(); it != m_layers.rend(); ++it)
		{
			bits remaining = it->previous.reduce(target ^ polynomial(value));
			for (int pivot = 95; pivot >= 0; --pivot)
			{
				if (remaining.test(pivot))
				{
					remaining ^= it->images[pivot];
					value ^= it->directions[pivot];
				}
			}
			if (!remaining.empty())
				throw std::runtime_error("target is outside the layer image");
		}
		if (evaluate(value) != target)
			throw std::runtime_error("signature preimage verification failed");
		return value;
	}
}
