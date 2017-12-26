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

#ifndef CHACHA_DETAIL_HPP_43939005
#define CHACHA_DETAIL_HPP_43939005

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <array>
#include <limits>
#include <type_traits>

#if (defined(_MSC_VER) && !defined(__clang__)) \
 && (defined(_M_X64) || _M_IX86_FP == 2)

#define __SSE2__
#define __SSSE3__

#endif

#if defined(__SSE2__)

#define CHACHA_SSE2_AVAILABLE

#include <xmmintrin.h>
#include <emmintrin.h>

#if defined(__SSSE3__)

#define CHACHA_SSSE3_AVAILABLE

#include <pmmintrin.h>
#include <tmmintrin.h>

#endif
#endif

namespace chacha {
namespace detail {

static_assert(std::is_same_v<
	std::underlying_type_t<std::byte>,
	std::uint8_t>, "std::byte is not 8 bit wide.");

template <std::size_t KeyBits>
struct key_bits {};

class cipher_rounds
{
	std::size_t _rounds{ 20 };

	explicit constexpr cipher_rounds(std::size_t rounds) noexcept
		: _rounds(rounds)
	{}

public:
	explicit constexpr cipher_rounds() noexcept = default;

	template <std::size_t Rounds>
	static constexpr cipher_rounds make() noexcept
	{
		static_assert(Rounds % 2 == 0, "Rounds must be divisible by 2.");
		return cipher_rounds(Rounds);
	}

	constexpr auto rounds() const noexcept
	{
		return _rounds;
	}
};

struct alignas(16) keypad_state
{
	std::array<std::uint32_t, 16> data;
};

template <std::size_t KeyBits>
keypad_state key_iv_setup(
	key_bits<KeyBits>,
	const std::byte* key_data,
	std::uint64_t nonce) noexcept
{
	static_assert(
		KeyBits == 128 || KeyBits == 256, "KeyBits must be 128 or 256.");

	static constexpr auto key_size{ KeyBits / 8 };

	static constexpr std::uint8_t kc0{ '0' +  key_size / 10 };
	static constexpr std::uint8_t kc1{ '0' +  key_size % 10 };

	static constexpr std::array<std::uint8_t, 16> pad
	{ {
		'e', 'x', 'p', 'a',
		'n', 'd', ' ', kc0,
		kc1, '-', 'b', 'y',
		't', 'e', ' ', 'k',
	} };

	keypad_state state{};

	const auto k0{ key_data };
	const auto k1{ KeyBits == 128 ? k0 : k0 + 16 };

	std::memcpy(&state.data[0], &pad[0], 16);
	std::memcpy(&state.data[4], k0, 16);
	std::memcpy(&state.data[8], k1, 16);
	std::memset(&state.data[12], 0x00, 8); // counter
	std::memcpy(&state.data[14], &nonce, 8);

	return state;
}

inline void memory_xor(
	std::byte* buffer,
	const std::byte* source0,
	const std::byte* source1,
	std::size_t bytes) noexcept
{
	for (std::size_t i{}; i < bytes; ++i)
	{
		buffer[i] = source0[i] ^ source1[i];
	}
}

/*
 * Loading and storing through memcpy to avoid
 * strict aliasing and potential alignment issues.
 * This will just generate a mov on x86.
 */

template <typename T>
static T memory_load(const std::byte* source) noexcept
{
	T value;
	std::memcpy(&value, source, sizeof value);
	return value;
}

template <typename T>
static void memory_store(std::byte* buffer, T value) noexcept
{
	std::memcpy(buffer, &value, sizeof value);
}

/*
 * GPR implementation.
 */

template <
	typename Word,
	typename = std::enable_if_t<std::is_unsigned_v<Word>>
>
static constexpr Word rol(Word w, unsigned amount) noexcept
{
	/*
	 * There is a way to implement this without
	 * needing a conditional, but not all compilers
	 * understand this pattern yet. Since all rotation
	 * amounts are compile-time constants,
	 * this is fine for now.
	 */

	constexpr auto word_bits{
		std::numeric_limits<Word>::digits
	};

	return (amount == 0) ? w :
		((w << amount) | (w >> (word_bits - amount)));
}

static void qround(
	std::uint32_t& r0,
	std::uint32_t& r1,
	std::uint32_t& r2,
	std::uint32_t& r3) noexcept
{
	r3 = rol(r3 ^ (r0 += r1), 16);
	r1 = rol(r1 ^ (r2 += r3), 12);
	r3 = rol(r3 ^ (r0 += r1), 8);
	r1 = rol(r1 ^ (r2 += r3), 7);
}

inline void transform_xor(
	keypad_state& key,
	cipher_rounds rounds,
	std::byte* buffer,
	const std::byte* source) noexcept
{
	auto r0{ key.data[0] };
	auto r1{ key.data[1] };
	auto r2{ key.data[2] };
	auto r3{ key.data[3] };
	auto r4{ key.data[4] };
	auto r5{ key.data[5] };
	auto r6{ key.data[6] };
	auto r7{ key.data[7] };
	auto r8{ key.data[8] };
	auto r9{ key.data[9] };
	auto r10{ key.data[10] };
	auto r11{ key.data[11] };
	auto r12{ key.data[12] };
	auto r13{ key.data[13] };
	auto r14{ key.data[14] };
	auto r15{ key.data[15] };

	// rounds.rounds() % 2 == 0 gets enforced at compile time
	// Equivalent to [0, rounds) - just reversed
	for (std::size_t i{ rounds.rounds() / 2 }; i-- > 0; )
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

	memory_store(buffer + 0,
		(r0 + key.data[0]) ^ memory_load<std::uint32_t>(source + 0));
	memory_store(buffer + 4,
		(r1 + key.data[1]) ^ memory_load<std::uint32_t>(source + 4));
	memory_store(buffer + 8,
		(r2 + key.data[2]) ^ memory_load<std::uint32_t>(source + 8));
	memory_store(buffer + 12,
		(r3 + key.data[3]) ^ memory_load<std::uint32_t>(source + 12));
	memory_store(buffer + 16,
		(r4 + key.data[4]) ^ memory_load<std::uint32_t>(source + 16));
	memory_store(buffer + 20,
		(r5 + key.data[5]) ^ memory_load<std::uint32_t>(source + 20));
	memory_store(buffer + 24,
		(r6 + key.data[6]) ^ memory_load<std::uint32_t>(source + 24));
	memory_store(buffer + 28,
		(r7 + key.data[7]) ^ memory_load<std::uint32_t>(source + 28));
	memory_store(buffer + 32,
		(r8 + key.data[8]) ^ memory_load<std::uint32_t>(source + 32));
	memory_store(buffer + 36,
		(r9 + key.data[9]) ^ memory_load<std::uint32_t>(source + 36));
	memory_store(buffer + 40,
		(r10 + key.data[10]) ^ memory_load<std::uint32_t>(source + 40));
	memory_store(buffer + 44,
		(r11 + key.data[11]) ^ memory_load<std::uint32_t>(source + 44));
	memory_store(buffer + 48,
		(r12 + key.data[12]) ^ memory_load<std::uint32_t>(source + 48));
	memory_store(buffer + 52,
		(r13 + key.data[13]) ^ memory_load<std::uint32_t>(source + 52));
	memory_store(buffer + 56,
		(r14 + key.data[14]) ^ memory_load<std::uint32_t>(source + 56));
	memory_store(buffer + 60,
		(r15 + key.data[15]) ^ memory_load<std::uint32_t>(source + 60));

	key.data[12] += 1;
}

#if !defined(CHACHA_SSE2_AVAILABLE)

static void transform_xor_3_blocks(
	keypad_state& key,
	cipher_rounds rounds,
	std::byte* buffer,
	const std::byte* source) noexcept
{
	transform_xor(key, rounds, buffer + 0, source + 0);
	transform_xor(key, rounds, buffer + 64, source + 64);
	transform_xor(key, rounds, buffer + 128, source + 128);
}

#else

/*
 * SSE2/SSSE3 implementation
 */

static __m128i pshufd1(__m128i v0) noexcept
{
	return _mm_shuffle_epi32(v0, _MM_SHUFFLE(0, 3, 2, 1));
}

static __m128i pshufd2(__m128i v0) noexcept
{
	return _mm_shuffle_epi32(v0, _MM_SHUFFLE(1, 0, 3, 2));
}

static __m128i pshufd3(__m128i v0) noexcept
{
	return _mm_shuffle_epi32(v0, _MM_SHUFFLE(2, 1, 0, 3));
}

template <std::size_t N>
static __m128i prold(__m128i v0) noexcept
{
	return N == 0 ? v0 :
		_mm_or_si128(_mm_slli_epi32(v0, N), _mm_srli_epi32(v0, 32 - N));

	static_assert(N < 32, "Invalid rotation amount");
}

#if defined(CHACHA_SSSE3_AVAILABLE)

template <>
__m128i prold<8>(__m128i v0) noexcept
{
	return _mm_shuffle_epi8(v0,
		_mm_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3));
}

template <>
__m128i prold<16>(__m128i v0) noexcept
{
	return _mm_shuffle_epi8(v0,
		_mm_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2));
}

#endif

template <std::size_t N>
static void triple_qround(
	__m128i& v0, __m128i& v1, __m128i& v3,
	__m128i& v4, __m128i& v5, __m128i& v7,
	__m128i& v8, __m128i& v9, __m128i& v11) noexcept
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

inline void transform_xor_3_blocks(
	keypad_state& key,
	cipher_rounds rounds,
	std::byte* buffer,
	const std::byte* source) noexcept
{
	const auto key_ptr{ reinterpret_cast<__m128i*>(key.data.data()) };
	const auto buf_ptr{ reinterpret_cast<__m128i*>(buffer) };
	const auto src_ptr{ reinterpret_cast<const __m128i*>(source) };

	auto k0{ _mm_load_si128(key_ptr + 0) };
	auto k1{ _mm_load_si128(key_ptr + 1) };
	auto k2{ _mm_load_si128(key_ptr + 2) };
	auto k3{ _mm_load_si128(key_ptr + 3) };

	auto v0{ k0 };
	auto v1{ k1 };
	auto v2{ k2 };
	auto v3{ k3 };

	auto v4{ k0 };
	auto v5{ k1 };
	auto v6{ k2 };
	auto v7{ _mm_add_epi32(v3, _mm_set_epi32(0, 0, 0, 1)) };

	auto v8{ k0 };
	auto v9{ k1 };
	auto v10{ k2 };
	auto v11{ _mm_add_epi32(v7, _mm_set_epi32(0, 0, 0, 1)) };

	// rounds.rounds() % 2 == 0 gets enforced at compile time
	// Equivalent to [0, rounds) - just reversed
	for (std::size_t i{ rounds.rounds() / 2 }; i-- > 0; )
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

	_mm_storeu_si128(buf_ptr + 0,
		_mm_xor_si128(v0, _mm_loadu_si128(src_ptr + 0)));
	_mm_storeu_si128(buf_ptr + 1,
		_mm_xor_si128(v1, _mm_loadu_si128(src_ptr + 1)));
	_mm_storeu_si128(buf_ptr + 2,
		_mm_xor_si128(v2, _mm_loadu_si128(src_ptr + 2)));
	_mm_storeu_si128(buf_ptr + 3,
		_mm_xor_si128(v3, _mm_loadu_si128(src_ptr + 3)));

	v4 = _mm_add_epi32(v4, k0);
	v5 = _mm_add_epi32(v5, k1);
	v6 = _mm_add_epi32(v6, k2);
	v7 = _mm_add_epi32(v7, k3);

	k3 = _mm_add_epi32(k3, _mm_set_epi32(0, 0, 0, 1));

	_mm_storeu_si128(buf_ptr + 4,
		_mm_xor_si128(v4, _mm_loadu_si128(src_ptr + 4)));
	_mm_storeu_si128(buf_ptr + 5,
		_mm_xor_si128(v5, _mm_loadu_si128(src_ptr + 5)));
	_mm_storeu_si128(buf_ptr + 6,
		_mm_xor_si128(v6, _mm_loadu_si128(src_ptr + 6)));
	_mm_storeu_si128(buf_ptr + 7,
		_mm_xor_si128(v7, _mm_loadu_si128(src_ptr + 7)));

	v8 = _mm_add_epi32(v8, k0);
	v9 = _mm_add_epi32(v9, k1);
	v10 = _mm_add_epi32(v10, k2);
	v11 = _mm_add_epi32(v11, k3);

	k3 = _mm_add_epi32(k3, _mm_set_epi32(0, 0, 0, 1));
	
	_mm_storeu_si128(buf_ptr + 8,
		_mm_xor_si128(v8, _mm_loadu_si128(src_ptr + 8)));
	_mm_storeu_si128(buf_ptr + 9,
		_mm_xor_si128(v9, _mm_loadu_si128(src_ptr + 9)));
	_mm_storeu_si128(buf_ptr + 10,
		_mm_xor_si128(v10, _mm_loadu_si128(src_ptr + 10)));
	_mm_storeu_si128(buf_ptr + 11,
		_mm_xor_si128(v11, _mm_loadu_si128(src_ptr + 11)));

	_mm_store_si128(key_ptr + 3, k3);
}

#endif

} // namespace detail
} // namespace chacha

#endif
