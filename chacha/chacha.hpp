#pragma once

#include "chacha_detail.hpp"

namespace chacha
{
	template <std::size_t KeyBits>
	struct key_bits
	{};

	struct cipher_rounds
	{
		std::size_t rounds;

		template <std::size_t Rounds>
		static cipher_rounds make()
		{
			static_assert(Rounds % 2 == 0, "Rounds must be divisible by 2.");
			return cipher_rounds(Rounds);
		}

	private:
		constexpr cipher_rounds(std::size_t rounds)
			: rounds(rounds)
		{}
	};

	class unbuffered_cipher
	{
		detail::keypad_state _keypad;

	public:
		template <std::size_t KeyBits>
		unbuffered_cipher(key_bits<KeyBits>, const void* key_data, std::uint64_t nonce)
			: _keypad(detail::key_iv_setup<KeyBits>(key_data, nonce))
		{}

		void set_block_index(std::uint64_t block_index)
		{
			std::memcpy(&_keypad.data[12], &block_index, 8);
		}

		void transform(void* buffer, const void* source, std::size_t bytes)
		{
			transform(cipher_rounds::make<20>(), buffer, source, bytes);
		}

		void transform(cipher_rounds rounds, void* buffer, const void* source, std::size_t bytes)
		{
			auto buf_ptr = static_cast<std::uint8_t*>(buffer);
			auto src_ptr = static_cast<const std::uint8_t*>(source);

			for (; bytes >= 192; bytes -= 192, buf_ptr += 192, src_ptr += 192)
			{
				detail::transform_xor_3_blocks(_keypad, rounds.rounds, buf_ptr, src_ptr);
			}
			
			if (bytes > 0)
			{
				if (bytes == 64)
				{
					detail::transform_xor(_keypad, rounds.rounds, buf_ptr, src_ptr);
				}
				else
				{
					alignas(16) std::array<std::uint8_t, 192> local_buffer = {};
					std::memcpy(&local_buffer[0], src_ptr, bytes);

					if (bytes > 64)
					{
						detail::transform_xor_3_blocks(_keypad, rounds.rounds, &local_buffer[0], &local_buffer[0]);
					}
					else
					{
						detail::transform_xor(_keypad, rounds.rounds, &local_buffer[0], &local_buffer[0]);
					}

					std::memcpy(buf_ptr, &local_buffer[0], bytes);
				}
			}
		}
	};

	class buffered_cipher
	{
		unbuffered_cipher _cipher;
		alignas(16) std::array<std::uint8_t, 192> _buffer;
		std::size_t _space = 0;

	public:
		template <std::size_t KeyBits>
		buffered_cipher(key_bits<KeyBits> kb, const void* key_data, std::uint64_t nonce)
			: _cipher(kb, key_data, nonce)
		{}

		void transform(void* buffer, const void* source, std::size_t bytes)
		{
			transform(cipher_rounds::make<20>(), buffer, source, bytes);
		}

		void transform(cipher_rounds rounds, void* buffer, const void* source, std::size_t bytes)
		{
			auto buf_ptr = static_cast<std::uint8_t*>(buffer);
			auto src_ptr = static_cast<const std::uint8_t*>(source);

			const auto rest_bytes = std::min(_space, bytes);

			if (rest_bytes > 0)
			{
				detail::memxor(buf_ptr, &_buffer[_buffer.size() - _space], src_ptr, rest_bytes);
				_space -= rest_bytes;
				bytes -= rest_bytes;
				buf_ptr += rest_bytes;
				src_ptr += rest_bytes;
			}

			// Either _space or bytes must be 0
			if (bytes > 0)
			{
				// Since bytes wasn't 0, _space must be.
				const auto direct_bytes = bytes / 64 * 64; // bytes & ~size_t(0b111111)

				if (direct_bytes > 0)
				{
					_cipher.transform(rounds, buf_ptr, src_ptr, direct_bytes);
					bytes -= direct_bytes;
					buf_ptr += direct_bytes;
					src_ptr += direct_bytes;
				}

				if (bytes > 0)
				{
					std::memset(&_buffer[0], 0x00, _buffer.size());
					_cipher.transform(rounds, &_buffer[0], &_buffer[0], _buffer.size());
					detail::memxor(buf_ptr, &_buffer[0], src_ptr, bytes);
					_space = _buffer.size() - bytes;
				}
			}
		}
	};
}
