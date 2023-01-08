#pragma once
#include <concepts>
#include <iostream>
#include <bitset>
#include <array>

namespace feistel {
	template<std::unsigned_integral T>
	inline constexpr T create_lower_mask(unsigned keep_bits) {
		constexpr auto SIZE = std::numeric_limits<T>::digits;
		T mask = ~0;
		mask <<= SIZE - keep_bits;
		mask >>= SIZE - keep_bits;
		return mask;
	}



	template<std::unsigned_integral Block>
	std::array<Block, 2> split_block(Block block) {
		static constexpr auto BLOCK_SIZE = std::numeric_limits<Block>::digits;
		static constexpr auto MASK = create_lower_mask<Block>(BLOCK_SIZE / 2);
		return {
			static_cast<Block>(block >> BLOCK_SIZE / 2),
			static_cast<Block>(block & MASK)};
	}



	template<std::unsigned_integral Block>
	Block merge_block(std::array<Block, 2> halfs) {
		static constexpr auto BLOCK_SIZE = std::numeric_limits<Block>::digits;
		return halfs[0] << BLOCK_SIZE/2 | halfs[1];
	}



	template<std::unsigned_integral Block>
	Block encrypt(Block block, auto f, auto keys) {
		static constexpr auto BLOCK_SIZE = std::numeric_limits<Block>::digits;
		auto [l, r] = split_block(block);

		std::cout 
			<< "L=" << std::bitset<BLOCK_SIZE>{l} << " "
			<< "R=" << std::bitset<BLOCK_SIZE>{r} << "\n";

		for(const auto & key : keys) {
			auto x = f(key, r);
			l ^= x;
			std::swap(l, r);
			std::cout 
				<< "L=" << std::bitset<BLOCK_SIZE>{l} << " "
				<< "R=" << std::bitset<BLOCK_SIZE>{r} << " "
				<< "F=" << std::bitset<BLOCK_SIZE>{x} << " "
				<< "K=" << std::bitset<BLOCK_SIZE>{key} << "\n";
		}

		std::swap(l,r);

		const auto result = merge_block<Block>({l,r});

		return result;
	}



	template<std::unsigned_integral Block>
	Block decrypt(Block block, auto f, auto keys) {
		std::reverse(std::begin(keys), std::end(keys));
		return encrypt(block, f, keys);
	}



	template<std::unsigned_integral T>
	T f_xor(T key, T r) {
		return key ^ r;
	}
}