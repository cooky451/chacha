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

#include "chacha/chacha.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace {

static_assert(std::is_same_v<
	std::underlying_type_t<std::byte>,
	std::uint8_t>, "std::byte is not 8 bit wide.");

using seconds_f32 = std::chrono::duration<float, std::ratio<1, 1>>;
using seconds_f64 = std::chrono::duration<double, std::ratio<1, 1>>;
using milliseconds_f32 = std::chrono::duration<float, std::milli>;
using milliseconds_f64 = std::chrono::duration<double, std::milli>;

template <typename Byte>
class BasicMemoryView
{
	Byte* _data{};
	std::size_t _size{};

public:
	constexpr BasicMemoryView() = default;

	constexpr BasicMemoryView(Byte* data, std::size_t size)
		: _data(data)
		, _size(size)
	{}

	template <typename Container>
	constexpr BasicMemoryView(Container& container)
		: BasicMemoryView(std::data(container), std::size(container))
	{}

	constexpr auto& operator [] (std::size_t i) const
	{
		return _data[i];
	}

	constexpr auto data() const
	{
		return _data;
	}

	constexpr auto size() const
	{
		return _size;
	}
};

using MemoryView = BasicMemoryView<std::byte>;
using ConstMemoryView = BasicMemoryView<const std::byte>;

constexpr std::byte hexCharToByte(char c)
{
	switch (c)
	{
		// default: is at the bottom
	case '0':
		return std::byte{ 0 };
	case '1':
		return std::byte{ 1 };
	case '2':
		return std::byte{ 2 };
	case '3':
		return std::byte{ 3 };
	case '4':
		return std::byte{ 4 };
	case '5':
		return std::byte{ 5 };
	case '6':
		return std::byte{ 6 };
	case '7':
		return std::byte{ 7 };
	case '8':
		return std::byte{ 8 };
	case '9':
		return std::byte{ 9 };
	case 'A':
	case 'a':
		return std::byte{ 10 };
	case 'B':
	case 'b':
		return std::byte{ 11 };
	case 'C':
	case 'c':
		return std::byte{ 12 };
	case 'D':
	case 'd':
		return std::byte{ 13 };
	case 'E':
	case 'e':
		return std::byte{ 14 };
	case 'F':
	case 'f':
		return std::byte{ 15 };

		/*
		 * Due to a VS 2017 bug, if the default is at the top
		 * of the switch, this code path is *always* taken
		 * when being executed at compile time.
		 */
	default:
		throw std::invalid_argument(
			"Character has no assigned hexadecimal value.");
	}
}

constexpr void hexStringToBytes(MemoryView buffer, std::string_view hexstr)
{
	if (std::size(hexstr) % 2 != 0)
	{
		throw std::invalid_argument("Hex string length is not even.");
	}

	if (std::size(buffer) < std::size(hexstr) / 2)
	{
		throw std::invalid_argument("Buffer is too small.");
	}

	for (std::size_t i{}; i < hexstr.size() / 2; ++i)
	{
		auto lhs{ hexCharToByte(hexstr[i * 2]) };
		auto rhs{ hexCharToByte(hexstr[i * 2 + 1]) };

		buffer[i] = (lhs << 4) | rhs;
	}
}

template <std::size_t N>
constexpr auto hexStringToBytes(const char(&hexstr)[N])
{
	std::array<std::byte, (N - 1) / 2> arr{};
	// char_traits::length isn't constexpr yet in VS 2017 ~~~~~
	hexStringToBytes(arr, std::string_view(hexstr, N - 1));
	return arr;
}

std::string bytesToHexString(ConstMemoryView bytes)
{
	std::string s(std::size(bytes) * 2, char{});

	for (std::size_t i{}; i < std::size(bytes); ++i)
	{
		static constexpr auto HEX_ASCII{ "0123456789abcdef" };
		static constexpr std::byte MASK{ 0xF };

		const auto lhs{ static_cast<std::uint8_t>(bytes[i] >> 4) };
		const auto rhs{ static_cast<std::uint8_t>(bytes[i] & MASK) };

		s[i * 2 + 0] = HEX_ASCII[lhs];
		s[i * 2 + 1] = HEX_ASCII[rhs];
	}

	return s;
}

std::ostream& operator << (std::ostream& lhs, MemoryView rhs)
{
	return lhs << bytesToHexString(rhs);
}

class ChachaTestCase
{
public:
	std::uint32_t keyBits;
	std::uint32_t rounds;
	std::array<std::byte, 8> iv;
	std::array<std::byte, 32> key;
	std::array<std::byte, 128> stream;
};

class TestCaseError : public std::logic_error
{
public:
	TestCaseError(const ChachaTestCase& test, 
		const std::array<std::byte, 128>& calculated)
		: std::logic_error(
			"Chacha test failed.\n"
			"Rounds: " + std::to_string(test.rounds) + "\n"
			"Key bits: " + std::to_string(test.keyBits) + "\n"
			"Key: [" + bytesToHexString(test.key) + "]\n"
			"IV: [" + bytesToHexString(test.iv) + "]\n"
			"Expected:   [" + bytesToHexString(test.stream) + "]\n"
			"Calculated: [" + bytesToHexString(calculated) + "]")
	{}
};

void runTestCase(const ChachaTestCase& test)
{
	auto rounds{ chacha::rounds20 };

	switch (test.rounds)
	{
	default:
		throw std::invalid_argument("Invalid number of rounds.");
	case 20:
		rounds = chacha::rounds20;
		break;
	case 12:
		rounds = chacha::rounds12;
		break;
	case 8:
		rounds = chacha::rounds8;
		break;
	}

	std::uint64_t nonce;
	std::memcpy(&nonce, std::data(test.iv), sizeof nonce);

	std::array<std::byte, 128> stream{};

	static constexpr std::size_t SPLIT_BYTES{ 77 };
	static constexpr std::size_t REST_BYTES{ std::size(stream) - SPLIT_BYTES };

	static_assert(std::size(stream) > SPLIT_BYTES, "This can't be good.");

	const auto ptr0{ std::data(stream) };
	const auto ptr1{ ptr0 + SPLIT_BYTES };

	if (test.keyBits == 128)
	{
		chacha::buffered_cipher cipher(
			chacha::key_bits_128, rounds, std::data(test.key), nonce);

		cipher.transform(ptr0, ptr0, SPLIT_BYTES);
		cipher.transform(ptr1, ptr1, REST_BYTES);
	}
	else if (test.keyBits == 256)
	{
		chacha::buffered_cipher cipher(
			chacha::key_bits_256, rounds, std::data(test.key), nonce);

		cipher.transform(ptr0, ptr0, SPLIT_BYTES);
		cipher.transform(ptr1, ptr1, REST_BYTES);
	}
	else
	{
		throw std::invalid_argument("Invalid key size.");
	}

	if (stream != test.stream)
	{
		throw TestCaseError(test, stream);
	}
}

void runAllTestCases()
{
	/*
	 * Source
	 * https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-01
	 */

	static constexpr std::array<ChachaTestCase, 12> TEST_CASES =
	{ {
		ChachaTestCase{
			128, 8,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"e28a5fa4a67f8c5defed3e6fb7303486"
				"aa8427d31419a729572d777953491120"
				"b64ab8e72b8deb85cd6aea7cb6089a10"
				"1824beeb08814a428aab1fa2c816081b"
				"8a26af448a1ba906368fd8c83831c18c"
				"ec8ced811a028e675b8d2be8fce08116"
				"5ceae9f1d1b7a975497749480569ceb8"
				"3de6a0a587d4984f19925f5d338e430d"),
		},
		ChachaTestCase{
			128, 12,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"e1047ba9476bf8ff312c01b4345a7d8c"
				"a5792b0ad467313f1dc412b5fdce3241"
				"0dea8b68bd774c36a920f092a04d3f95"
				"274fbeff97bc8491fcef37f85970b450"
				"1d43b61a8f7e19fceddef368ae6bfb11"
				"101bd9fd3e4d127de30db2db1b472e76"
				"426803a45e15b962751986ef1d9d50f5"
				"98a5dcdc9fa529a28357991e784ea20f"),
		},
		ChachaTestCase{
			128, 20,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"89670952608364fd00b2f90936f031c8"
				"e756e15dba04b8493d00429259b20f46"
				"cc04f111246b6c2ce066be3bfb32d9aa"
				"0fddfbc12123d4b9e44f34dca05a103f"
				"6cd135c2878c832b5896b134f6142a9d"
				"4d8d0d8f1026d20a0a81512cbce6e975"
				"8a7143d021978022a384141a80cea306"
				"2f41f67a752e66ad3411984c787e30ad"),
		},
		ChachaTestCase{
			256, 8,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"3e00ef2f895f40d67f5bb8e81f09a5a1"
				"2c840ec3ce9a7f3b181be188ef711a1e"
				"984ce172b9216f419f445367456d5619"
				"314a42a3da86b001387bfdb80e0cfe42"
				"d2aefa0deaa5c151bf0adb6c01f2a5ad"
				"c0fd581259f9a2aadcf20f8fd566a26b"
				"5032ec38bbc5da98ee0c6f568b872a65"
				"a08abf251deb21bb4b56e5d8821e68aa"),
		},
		ChachaTestCase{
			256, 12,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"9bf49a6a0755f953811fce125f2683d5"
				"0429c3bb49e074147e0089a52eae155f"
				"0564f879d27ae3c02ce82834acfa8c79"
				"3a629f2ca0de6919610be82f411326be"
				"0bd58841203e74fe86fc71338ce0173d"
				"c628ebb719bdcbcc151585214cc089b4"
				"42258dcda14cf111c602b8971b8cc843"
				"e91e46ca905151c02744a6b017e69316"),
		},
		ChachaTestCase{
			256, 20,
			hexStringToBytes("0000000000000000"),
			hexStringToBytes(
				"00000000000000000000000000000000"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"76b8e0ada0f13d90405d6ae55386bd28"
				"bdd219b8a08ded1aa836efcc8b770dc7"
				"da41597c5157488d7724e03fb8d84a37"
				"6a43b8f41518a11cc387b669b2ee6586"
				"9f07e7be5551387a98ba977c732d080d"
				"cb0f29a048e3656912c6533e32ee7aed"
				"29b721769ce64e43d57133b074d839d5"
				"31ed1f28510afb45ace10a1f4b794d6f"),
		},
		ChachaTestCase{
			128, 8,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"6a870108859f679118f3e205e2a56a68"
				"26ef5a60a4102ac8d4770059fcb7c7ba"
				"e02f5ce004a6bfbbea53014dd82107c0"
				"aa1c7ce11b7d78f2d50bd3602bbd2594"
				"0560bb6a84289e0b38f5dd21d6ef6d77"
				"37e3ec0fb772da2c71c2397762e5dbbb"
				"f449e3d1639ccbfa3e069c4d871ed639"
				"5b22aaf35c8da6de2dec3d77880da8e8"),
		},
		ChachaTestCase{
			128, 12,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"00000000000000000000000000000000"),
			hexStringToBytes(
				"b02bd81eb55c8f68b5e9ca4e307079bc"
				"225bd22007eddc6702801820709ce098"
				"07046a0d2aa552bfdbb49466176d56e3"
				"2d519e10f5ad5f2746e241e09bdf9959"
				"17be0873edde9af5b86246441ce41019"
				"5baede41f8bdab6ad253226382ee383e"
				"3472f945a5e6bd628c7a582bcf8f8998"
				"70596a58dab83b51a50c7dbb4f3e6e76"),
		},
		ChachaTestCase{
			128, 20,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"1f68ed2e194c79fbc6aebee1a667975d"),
			hexStringToBytes(
				"826abdd84460e2e9349f0ef4af5b179b"
				"426e4b2d109a9c5bb44000ae51bea90a"
				"496beeef62a76850ff3f0402c4ddc99f"
				"6db07f151c1c0dfac2e56565d6289625"
				"5b23132e7b469c7bfb88fa95d44ca5ae"
				"3e45e848a4108e98bad7a9eb15512784"
				"a6a9e6e591dce674120acaf9040ff50f"
				"f3ac30ccfb5e14204f5e4268b90a8804"),
		},
		ChachaTestCase{
			256, 8,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"1f68ed2e194c79fbc6aebee1a667975d"),
			hexStringToBytes(
				"838751b42d8ddd8a3d77f48825a2ba75"
				"2cf4047cb308a5978ef274973be374c9"
				"6ad848065871417b08f034e681fe46a9"
				"3f7d5c61d1306614d4aaf257a7cff08b"
				"16f2fda170cc18a4b58a2667ed962774"
				"af792a6e7f3c77992540711a7a136d7e"
				"8a2f8d3f93816709d45a3fa5f8ce72fd"
				"e15be7b841acba3a2abd557228d9fe4f"),
		},
		ChachaTestCase{
			256, 12,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"1f68ed2e194c79fbc6aebee1a667975d"),
			hexStringToBytes(
				"1482072784bc6d06b4e73bdc118bc010"
				"3c7976786ca918e06986aa251f7e9cc1"
				"b2749a0a16ee83b4242d2e99b08d7c20"
				"092b80bc466c87283b61b1b39d0ffbab"
				"d94b116bc1ebdb329b9e4f620db69554"
				"4a8e3d9b68473d0c975a46ad966ed631"
				"e42aff530ad5eac7d8047adfa1e5113c"
				"91f3e3b883f1d189ac1c8fe07ba5a42b"),
		},
		ChachaTestCase{
			256, 20,
			hexStringToBytes("1ada31d5cf688221"),
			hexStringToBytes(
				"c46ec1b18ce8a878725a37e780dfb735"
				"1f68ed2e194c79fbc6aebee1a667975d"),
			hexStringToBytes(
				"f63a89b75c2271f9368816542ba52f06"
				"ed49241792302b00b5e8f80ae9a473af"
				"c25b218f519af0fdd406362e8d69de7f"
				"54c604a6e00f353f110f771bdca8ab92"
				"e5fbc34e60a1d9a9db17345b0a402736"
				"853bf910b060bdf1f897b6290f01d138"
				"ae2c4c90225ba9ea14d518f55929dea0"
				"98ca7a6ccfe61227053c84e49a4a3332"),
		},
	} };

	for (auto& test : TEST_CASES)
	{
		runTestCase(test);
	}

	std::cout << "All tests successful.\n";
}

template <typename F>
double benchAndCalcBandwidth(
	F func,
	std::chrono::milliseconds timeLimit,
	std::uint64_t bytesPerIteration)
{
	namespace cr = std::chrono;

	const auto start{ cr::high_resolution_clock::now() };

	auto now{ start };

	unsigned counter{};

	while (now - start < timeLimit)
	{
		func();
		counter += 1;
		now = cr::high_resolution_clock::now();
	}

	const seconds_f64 elapsed{ now - start };
	const auto totalBytes{ bytesPerIteration * counter };
	const auto bandwidth{ totalBytes / elapsed.count() };

	// Makes output nicer.
	if (counter % 2 == 0)
	{
		func();
	}

	return bandwidth;
}

void benchmark()
{
	static constexpr auto key{ hexStringToBytes(
		"c46ec1b18ce8a878725a37e780dfb735"
		"1f68ed2e194c79fbc6aebee1a667975d") };

	static constexpr std::chrono::milliseconds timeLimit{ 1500 };

	/*
	 * The OS won't map the memory until it is actually touched,
	 * so don't change this to unique_ptr<> or similar.
	 */

	std::vector<std::byte> buf(2 * 1024 * 1024);

	std::cout
		<< "Running benchmarks for 1.5 seconds with buffer size ["
		<< std::size(buf) << "] including stream xor...\n";

	std::cout << "Name\t\tBandwidth\t\tNoOptTag\n";

	chacha::unbuffered_cipher cipher(
		chacha::key_bits_256, std::data(key), 0);

	{
		const auto bandwidth{ benchAndCalcBandwidth([&] {
			cipher.transform(chacha::rounds20, 0,
				std::data(buf), std::data(buf), std::size(buf));
		}, timeLimit, std::size(buf)) };


		const auto mibps{ std::round(bandwidth / 1024 / 1024) };

		std::cout
			<< "Chacha20\t" << mibps << " MiB/s\t\t"
			<< MemoryView{ std::data(buf), 16 } << std::endl;
	}

	{
		const auto bandwidth{ benchAndCalcBandwidth([&] {
			cipher.transform(chacha::rounds12, 0,
				std::data(buf), std::data(buf), std::size(buf));
		}, timeLimit, std::size(buf)) };

		const auto mibps{ std::round(bandwidth / 1024 / 1024) };

		std::cout
			<< "Chacha12\t" << mibps << " MiB/s\t\t"
			<< MemoryView{ std::data(buf), 16 } << std::endl;
	}

	{
		const auto bandwidth{ benchAndCalcBandwidth([&] {
			cipher.transform(chacha::rounds8, 0,
				std::data(buf), std::data(buf), std::size(buf));
		}, timeLimit, std::size(buf)) };

		const auto mibps{ std::round(bandwidth / 1024 / 1024) };

		std::cout
			<< "Chacha8 \t" << mibps << " MiB/s\t\t"
			<< MemoryView{ std::data(buf), 16 } << std::endl;
	}
}
} // namespace

int main() try
{
	runAllTestCases();
	benchmark();
}
catch (std::exception& e)
{
	std::cerr << "Error: " << e.what() << '\n';
}
catch (...)
{
	std::cerr << "Unknown error occured.\n";
}
