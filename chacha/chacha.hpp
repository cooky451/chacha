/*
 * Copyright (c) 2016 - 2017 cooky451
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef CHACHA_HPP_74350828
#define CHACHA_HPP_74350828

#include "chacha_detail.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <array>

namespace chacha {

static constexpr auto rounds20{ detail::cipher_rounds::make<20>() };
static constexpr auto rounds12{ detail::cipher_rounds::make<12>() };
static constexpr auto rounds8{ detail::cipher_rounds::make<8>() };

static constexpr auto key_bits_128{ detail::key_bits<128>{} };
static constexpr auto key_bits_256{ detail::key_bits<256>{} };

struct block_index_continue_tag {};

/*
 * ==== class buffered_cipher ====
 *
 * For this cipher, transform works like a continuous byte stream.
 * It doesn't matter if you make three calls to transform()
 * with 10, 10 and 20 bytes or two calls to transform()
 * with 20 and 20 bytes, the result will be the same.
 * The block index will be increased as necessary.
 *
 * ==== class buffered_cipher ====
 *
 * buffered_cipher(key_bits kb, cipher_rounds rounds,
 *     const std::byte* key_data, std::uint64_t nonce);
 *
 * void transform(
 *     std::byte* buffer, const std::byte* source, std::size_t bytes);
 */

/*
 * ==== class unbuffered_cipher ====
 *
 * For this cipher, transform works on blocks of 64 bytes.
 * Every call to transform() will increase the block
 * index by (bytes / 64 + ((bytes % 64) != 0)) -
 * i.e. every "started" block is fully consumed.
 *
 * ==== class unbuffered_cipher ====
 *
 * unbuffered_cipher(key_bits kb,
 *     const std::byte* key_data, std::uint64_t nonce);
 *
 * void transform(std::uint64_t block_index,
 *     std::byte* buffer, const std::byte* source, std::size_t bytes);
 *
 * void transform(block_index_continue_tag tag,
 *     std::byte* buffer, const std::byte* source, std::size_t bytes);
 *
 * void transform(detail::cipher_rounds rounds, std::uint64_t block_index,
 *     std::byte* buffer, const std::byte* source, std::size_t bytes)
 *
 * void transform(detail::cipher_rounds rounds, block_index_continue_tag tag,
 *     std::byte* buffer, const std::byte* source, std::size_t bytes)
 */

class unbuffered_cipher
{
	static constexpr auto default_rounds{ rounds20 };

	detail::keypad_state _keypad;

public:
	template <std::size_t KeyBits>
	unbuffered_cipher(detail::key_bits<KeyBits> kb,
		const std::byte* key_data, std::uint64_t nonce) noexcept
		: _keypad(detail::key_iv_setup(kb, key_data, nonce))
	{}

	void transform(std::uint64_t block_index,
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		transform(default_rounds, block_index, buffer, source, bytes);
	}

	void transform(block_index_continue_tag tag,
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		transform(default_rounds, tag, buffer, source, bytes);
	}

	void transform(detail::cipher_rounds rounds, std::uint64_t block_index,
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		set_block_index(block_index);
		transform_impl(rounds, buffer, source, bytes);
	}

	void transform(detail::cipher_rounds rounds, block_index_continue_tag,
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		transform_impl(rounds, buffer, source, bytes);
	}

private:
	void set_block_index(std::uint64_t block_index) noexcept
	{
		std::memcpy(&_keypad.data[12], &block_index, 8);
	}

	void transform_impl(detail::cipher_rounds rounds,
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		for (; bytes >= 192; bytes -= 192, buffer += 192, source += 192)
		{
			detail::transform_xor_3_blocks(_keypad, rounds, buffer, source);
		}

		for (; bytes >= 64; bytes -= 64, buffer += 64, source += 64)
		{
			detail::transform_xor(_keypad, rounds, buffer, source);
		}

		if (bytes > 0)
		{
			std::array<std::byte, 64> local_buffer{};

			std::memcpy(&local_buffer[0], source, bytes);

			detail::transform_xor(
				_keypad,
				rounds,
				&local_buffer[0],
				&local_buffer[0]);

			std::memcpy(buffer, &local_buffer[0], bytes);
		}
	}
};

class buffered_cipher
{
	unbuffered_cipher _cipher;
	std::array<std::byte, 192> _buffer; // gets initialized in transform()
	std::size_t _space{};
	detail::cipher_rounds _rounds;

public:
	template <std::size_t KeyBits>
	buffered_cipher(
		detail::key_bits<KeyBits> kb,
		detail::cipher_rounds rounds,
		const std::byte* key_data,
		std::uint64_t nonce) noexcept
		: _cipher(kb, key_data, nonce)
		, _rounds(rounds)
	{}

	void transform(
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		const auto rest_bytes{ std::min(_space, bytes) };

		if (rest_bytes > 0)
		{
			detail::memory_xor(
				buffer,
				&_buffer[_buffer.size() - _space],
				source,
				rest_bytes);

			_space -= rest_bytes;
			bytes -= rest_bytes;
			buffer += rest_bytes;
			source += rest_bytes;
		}

		/*
		 * At this point, either _space or bytes must be 0.
		 */

		if (bytes > 0)
		{
			/*
			 * Since bytes isn't 0, _space must be.
			 */

			handle_out_of_space(buffer, source, bytes);
		}
	}

private:
	void handle_out_of_space(
		std::byte* buffer, const std::byte* source, std::size_t bytes) noexcept
	{
		/*
		 * assert(_space == 0)!
		 */

		//         equivalent to bytes & ~std::size_t{ 0b111111 }
		const auto direct_bytes{ bytes / 64 * 64 };

		if (direct_bytes > 0)
		{
			_cipher.transform(
				_rounds,
				block_index_continue_tag{},
				buffer,
				source,
				direct_bytes);

			bytes -= direct_bytes;
			buffer += direct_bytes;
			source += direct_bytes;
		}

		if (bytes > 0)
		{
			_buffer = {};

			_cipher.transform(
				_rounds,
				block_index_continue_tag{},
				&_buffer[0],
				&_buffer[0],
				_buffer.size());

			detail::memory_xor(buffer, &_buffer[0], source, bytes);

			_space = _buffer.size() - bytes;
		}
	}
};
} // namespace chacha

#endif
