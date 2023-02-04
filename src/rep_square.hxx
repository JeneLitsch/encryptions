#pragma once
#include <cstdint>
#include <concepts>

namespace crypto {
	template<std::unsigned_integral Block>
	Block repeated_squaring(Block plain, Block exp, Block mod) {
		static constexpr auto BITS = std::numeric_limits<Block>::digits;
		Block value = 1;
		for(int i = BITS - 1; i >= 0; --i) {
			const auto bit = static_cast<bool>((exp >> (i)) & 1);
			value *= value;
			if(bit) value *= plain;
			value %= mod;
		}
		return value;
	}
}