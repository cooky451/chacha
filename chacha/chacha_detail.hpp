#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <algorithm>
#include <array>

#if defined(__SSE2__) || (defined(_MSC_VER) && (defined(_M_X64) || _M_IX86_FP == 2))
#define CHACHA_SSE2_AVAILABLE
#if defined(__SSSE3__) || (defined(_MSC_VER) && (defined(_M_X64) || _M_IX86_FP == 2))
#define CHACHA_SSSE3_AVAILABLE
#endif
#endif

namespace chacha
{
	namespace detail
	{
		static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

		struct alignas(16) keypad_state
		{
			std::array<std::uint32_t, 16> data;
		};

		template <std::size_t KeyBits>
		static keypad_state key_iv_setup(const void* key_data, std::uint64_t nonce)
		{
			static_assert(KeyBits == 128 || KeyBits == 256, "KeyBits must be 128 or 256.");

			constexpr std::size_t key_size = KeyBits / 8;
			constexpr std::uint8_t kc0 = '0' + std::uint8_t{ key_size / 10 };
			constexpr std::uint8_t kc1 = '0' + std::uint8_t{ key_size % 10 };
			constexpr std::array<std::uint8_t, 16> pad = 
			{
				'e', 'x', 'p', 'a',
				'n', 'd', ' ', kc0,
				kc1, '-', 'b', 'y',
				't', 'e', ' ', 'k',
			};

			keypad_state state;

			const auto k0 = static_cast<const std::uint8_t*>(key_data);
			const auto k1 = KeyBits == 128 ? k0 : k0 + 16;

			std::memcpy(&state.data[0], &pad[0], 16);
			std::memcpy(&state.data[4], k0, 16);
			std::memcpy(&state.data[8], k1, 16);
			std::memset(&state.data[12], 0x00, 8); // counter
			std::memcpy(&state.data[14], &nonce, 8);

			return state;
		}

		void memxor(void* buffer, const void* source0, const void* source1, std::size_t bytes)
		{
			auto buf_ptr = static_cast<std::uint8_t*>(buffer);
			auto src0_ptr = static_cast<const std::uint8_t*>(source0);
			auto src1_ptr = static_cast<const std::uint8_t*>(source1);

			for (std::size_t i = 0; i < bytes; ++i)
			{
				buf_ptr[i] = src0_ptr[i] ^ src1_ptr[i];
			}
		}

		/* GPR implementation.
		 * 
		 */

		template <typename Word>
		constexpr Word shr(Word w, unsigned amount)
		{
			return w >> amount;
		}

		template <typename Word>
		constexpr Word shl(Word w, unsigned amount)
		{
			return w << amount;
		}

		template <typename Word>
		constexpr Word ror(Word w, unsigned amount)
		{
			return shr(w, amount) | shl(w, std::numeric_limits<Word>::digits - amount);
		}

		template <typename Word>
		constexpr Word rol(Word w, unsigned amount)
		{
			return shl(w, amount) | shr(w, std::numeric_limits<Word>::digits - amount);
		}

		// Loading and storing through memcpy to avoid strict aliasing issues.
		// This will just generate a mov.
		template <typename T>
		static T memcpy_ldr(const void* source)
		{
			T value;
			std::memcpy(&value, source, sizeof value);
			return value;
		}

		template <typename T>
		static void memcpy_str(void* buffer, T value)
		{
			std::memcpy(buffer, &value, sizeof value);
		}

		static void qround(std::uint32_t& r0, std::uint32_t& r1, std::uint32_t& r2, std::uint32_t& r3)
		{
			r3 = rol(r3 ^ (r0 += r1), 16);
			r1 = rol(r1 ^ (r2 += r3), 12);
			r3 = rol(r3 ^ (r0 += r1), 8);
			r1 = rol(r1 ^ (r2 += r3), 7);
		}

		static void transform_xor(keypad_state& key, std::size_t rounds, void* buffer, const void* source)
		{
			const auto buf_ptr = static_cast<std::uint32_t*>(buffer);
			const auto src_ptr = static_cast<const std::uint32_t*>(source);

			auto r0 = key.data[0];
			auto r1 = key.data[1];
			auto r2 = key.data[2];
			auto r3 = key.data[3];
			auto r4 = key.data[4];
			auto r5 = key.data[5];
			auto r6 = key.data[6];
			auto r7 = key.data[7];
			auto r8 = key.data[8];
			auto r9 = key.data[9];
			auto r10 = key.data[10];
			auto r11 = key.data[11];
			auto r12 = key.data[12];
			auto r13 = key.data[13];
			auto r14 = key.data[14];
			auto r15 = key.data[15];

			// assert(rounds % 2 == 0) // Gets enforced through higher level compile-time check.
			for (std::size_t i = rounds / 2; i-- > 0; )
			{
				qround(r0, r4, r8, r12);
				qround(r1, r5, r9, r13);
				qround(r2, r6, r10, r14);
				qround(r3, r7, r11, r15);

				qround(r0, r5, r10, r15);
				qround(r1, r6, r11, r12);
				qround(r2, r7, r8, r13);
				qround(r3, r4, r9, r14);
			}

			memcpy_str(buf_ptr + 0, (r0 + key.data[0]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 0));
			memcpy_str(buf_ptr + 1, (r1 + key.data[1]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 1));
			memcpy_str(buf_ptr + 2, (r2 + key.data[2]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 2));
			memcpy_str(buf_ptr + 3, (r3 + key.data[3]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 3));
			memcpy_str(buf_ptr + 4, (r4 + key.data[4]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 4));
			memcpy_str(buf_ptr + 5, (r5 + key.data[5]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 5));
			memcpy_str(buf_ptr + 6, (r6 + key.data[6]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 6));
			memcpy_str(buf_ptr + 7, (r7 + key.data[7]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 7));
			memcpy_str(buf_ptr + 8, (r8 + key.data[8]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 8));
			memcpy_str(buf_ptr + 9, (r9 + key.data[9]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 9));
			memcpy_str(buf_ptr + 10, (r10 + key.data[10]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 10));
			memcpy_str(buf_ptr + 11, (r11 + key.data[11]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 11));
			memcpy_str(buf_ptr + 12, (r12 + key.data[12]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 12));
			memcpy_str(buf_ptr + 13, (r13 + key.data[13]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 13));
			memcpy_str(buf_ptr + 14, (r14 + key.data[14]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 14));
			memcpy_str(buf_ptr + 15, (r15 + key.data[15]) ^ memcpy_ldr<std::uint32_t>(src_ptr + 15));

			key.data[12] += 1;
		}

		/* SSE2/SSSE3 implementation
		 * 
		 */

#if !defined(CHACHA_SSE2_AVAILABLE)
		static void transform_xor_3_blocks(keypad_state& key, std::size_t rounds, void* buffer, const void* source)
		{
			const auto buf_ptr = static_cast<std::uint8_t*>(buffer);
			const auto src_ptr = static_cast<const std::uint8_t*>(source);

			transform_xor(key, rounds, buf_ptr + 0, src_ptr + 0);
			transform_xor(key, rounds, buf_ptr + 64, src_ptr + 64);
			transform_xor(key, rounds, buf_ptr + 128, src_ptr + 128);
		}
#else
		static __m128i pshufd1(__m128i v0)
		{
			return _mm_shuffle_epi32(v0, _MM_SHUFFLE(0, 3, 2, 1));
		}

		static __m128i pshufd2(__m128i v0)
		{
			return _mm_shuffle_epi32(v0, _MM_SHUFFLE(1, 0, 3, 2));
		}

		static __m128i pshufd3(__m128i v0)
		{
			return _mm_shuffle_epi32(v0, _MM_SHUFFLE(2, 1, 0, 3));
		}

		template <std::size_t N>
		static __m128i prold(__m128i v0)
		{
			return _mm_or_si128(_mm_slli_epi32(v0, N), _mm_srli_epi32(v0, 32 - N));
		}
#if defined(CHACHA_SSSE3_AVAILABLE)
		template <>
		__m128i prold<8>(__m128i v0)
		{
			return _mm_shuffle_epi8(v0, _mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3));
		}

		template <>
		__m128i prold<16>(__m128i v0)
		{
			return _mm_shuffle_epi8(v0, _mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
		}
#endif
		template <std::size_t N>
		static void triple_qround(
			__m128i& v0, __m128i& v1, __m128i& v3,
			__m128i& v4, __m128i& v5, __m128i& v7,
			__m128i& v8, __m128i& v9, __m128i& v11)
		{
			v0 = _mm_add_epi32(v0, v1);
			v4 = _mm_add_epi32(v4, v5);
			v8 = _mm_add_epi32(v8, v9);

			v3 = _mm_xor_si128(v3, v0);
			v7 = _mm_xor_si128(v7, v4);
			v11 = _mm_xor_si128(v11, v8);

			v3 = prold<N>(v3);
			v7 = prold<N>(v7);
			v11 = prold<N>(v11);
		}

		static void transform_xor_3_blocks(keypad_state& key, std::size_t rounds, void* buffer, const void* source)
		{
			// Violates strict aliasing, but Intel was apparently not a big fan of ISO-C.
			// At least they fixed it for AVX2 instructions, which all take void*.
			// Considering these are intrinsics, any sane compiler should do the right thing.

			const auto key_ptr = reinterpret_cast<__m128i*>(key.data.data());
			const auto buf_ptr = static_cast<__m128i*>(buffer);
			const auto src_ptr = static_cast<const __m128i*>(source);

			auto k0 = _mm_load_si128(key_ptr + 0);
			auto k1 = _mm_load_si128(key_ptr + 1);
			auto k2 = _mm_load_si128(key_ptr + 2);
			auto k3 = _mm_load_si128(key_ptr + 3);

			auto v0 = k0;
			auto v1 = k1;
			auto v2 = k2;
			auto v3 = k3;

			auto v4 = k0;
			auto v5 = k1;
			auto v6 = k2;
			auto v7 = _mm_add_epi32(v3, _mm_set_epi32(0, 0, 0, 1));

			auto v8 = k0;
			auto v9 = k1;
			auto v10 = k2;
			auto v11 = _mm_add_epi32(v7, _mm_set_epi32(0, 0, 0, 1));

			// assert(rounds % 2 == 0) // Gets enforced through higher level compile-time check.
			for (std::size_t i = rounds / 2; i-- > 0; )
			{
				triple_qround<16>(v0, v1, v3, v4, v5, v7, v8, v9, v11);
				triple_qround<12>(v2, v3, v1, v6, v7, v5, v10, v11, v9);
				triple_qround<8>(v0, v1, v3, v4, v5, v7, v8, v9, v11);
				triple_qround<7>(v2, v3, v1, v6, v7, v5, v10, v11, v9);

				v1 = pshufd1(v1);
				v2 = pshufd2(v2);
				v3 = pshufd3(v3);
				v5 = pshufd1(v5);
				v6 = pshufd2(v6);
				v7 = pshufd3(v7);
				v9 = pshufd1(v9);
				v10 = pshufd2(v10);
				v11 = pshufd3(v11);

				triple_qround<16>(v0, v1, v3, v4, v5, v7, v8, v9, v11);
				triple_qround<12>(v2, v3, v1, v6, v7, v5, v10, v11, v9);
				triple_qround<8>(v0, v1, v3, v4, v5, v7, v8, v9, v11);
				triple_qround<7>(v2, v3, v1, v6, v7, v5, v10, v11, v9);

				v1 = pshufd3(v1);
				v2 = pshufd2(v2);
				v3 = pshufd1(v3);
				v5 = pshufd3(v5);
				v6 = pshufd2(v6);
				v7 = pshufd1(v7);
				v9 = pshufd3(v9);
				v10 = pshufd2(v10);
				v11 = pshufd1(v11);
			}

			v0 = _mm_add_epi32(v0, k0);
			v1 = _mm_add_epi32(v1, k1);
			v2 = _mm_add_epi32(v2, k2);
			v3 = _mm_add_epi32(v3, k3);

			k3 = _mm_add_epi32(k3, _mm_set_epi32(0, 0, 0, 1));

			v4 = _mm_add_epi32(v4, k0);
			v5 = _mm_add_epi32(v5, k1);
			v6 = _mm_add_epi32(v6, k2);
			v7 = _mm_add_epi32(v7, k3);

			k3 = _mm_add_epi32(k3, _mm_set_epi32(0, 0, 0, 1));

			v8 = _mm_add_epi32(v8, k0);
			v9 = _mm_add_epi32(v9, k1);
			v10 = _mm_add_epi32(v10, k2);
			v11 = _mm_add_epi32(v11, k3);

			k3 = _mm_add_epi32(k3, _mm_set_epi32(0, 0, 0, 1));

			_mm_storeu_si128(buf_ptr + 0, _mm_xor_si128(v0, _mm_loadu_si128(src_ptr + 0)));
			_mm_storeu_si128(buf_ptr + 1, _mm_xor_si128(v1, _mm_loadu_si128(src_ptr + 1)));
			_mm_storeu_si128(buf_ptr + 2, _mm_xor_si128(v2, _mm_loadu_si128(src_ptr + 2)));
			_mm_storeu_si128(buf_ptr + 3, _mm_xor_si128(v3, _mm_loadu_si128(src_ptr + 3)));
			_mm_storeu_si128(buf_ptr + 4, _mm_xor_si128(v4, _mm_loadu_si128(src_ptr + 4)));
			_mm_storeu_si128(buf_ptr + 5, _mm_xor_si128(v5, _mm_loadu_si128(src_ptr + 5)));
			_mm_storeu_si128(buf_ptr + 6, _mm_xor_si128(v6, _mm_loadu_si128(src_ptr + 6)));
			_mm_storeu_si128(buf_ptr + 7, _mm_xor_si128(v7, _mm_loadu_si128(src_ptr + 7)));
			_mm_storeu_si128(buf_ptr + 8, _mm_xor_si128(v8, _mm_loadu_si128(src_ptr + 8)));
			_mm_storeu_si128(buf_ptr + 9, _mm_xor_si128(v9, _mm_loadu_si128(src_ptr + 9)));
			_mm_storeu_si128(buf_ptr + 10, _mm_xor_si128(v10, _mm_loadu_si128(src_ptr + 10)));
			_mm_storeu_si128(buf_ptr + 11, _mm_xor_si128(v11, _mm_loadu_si128(src_ptr + 11)));

			_mm_store_si128(key_ptr + 3, k3);
		}
#endif
	}
}
