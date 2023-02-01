#include <string>
#include <vector>
#include <iostream>
#include "hexed.hxx"

std::vector<std::uint8_t> pad(const std::string & input, std::uint64_t block_size) {
	std::vector<std::uint8_t> padded { std::begin(input), std::end(input) };
	while(std::size(padded) % 8) padded.push_back(0);
	return padded;
}



constexpr auto merkle_damgard_construction(std::uint64_t init, auto compress) {
	
	return [init, compress] (const std::string & str) {
		const auto data = pad(str, 8);
		auto it = std::cbegin(data);

		std::uint64_t state = init;
		while(it != std::end(data)) {
			const std::uint64_t block =
				+ (static_cast<std::uint64_t>(*(it + 7)) << 0 * 8)
				+ (static_cast<std::uint64_t>(*(it + 6)) << 1 * 8)
				+ (static_cast<std::uint64_t>(*(it + 5)) << 2 * 8)
				+ (static_cast<std::uint64_t>(*(it + 4)) << 3 * 8)
				+ (static_cast<std::uint64_t>(*(it + 3)) << 4 * 8)
				+ (static_cast<std::uint64_t>(*(it + 2)) << 5 * 8)
				+ (static_cast<std::uint64_t>(*(it + 1)) << 6 * 8)
				+ (static_cast<std::uint64_t>(*(it + 0)) << 7 * 8);

			state = compress(state, block);		
			std::advance(it, 8);
		}
		return state;
	};
}


namespace sponge {
	std::uint64_t absorb(const std::string & input, const auto & f, std::uint64_t r) {
		std::size_t index = 0;
		const auto eos = [&] () -> bool {
			return index >= std::size(input);
		};
		const auto fetch = [&] () -> std::uint8_t {
			return (!eos()) ? input[++index] : '_';
		};
		
		std::uint64_t state = 0;
		while(!eos()) {
			std::uint64_t block = 0;
			for(std::uint64_t r_i = 0; r_i < r; ++r_i) {
				block |= static_cast<std::uint64_t>(fetch()) << r_i * 8;
			}
			state = f(state^block);
		}

		return state;
	}



	std::vector<std::uint8_t> squeeze(std::uint64_t state, const auto & f, std::uint64_t r, std::uint64_t squeeze_rounds) {
		std::vector<std::uint8_t> hash_result;

		for(std::uint64_t i = 0; i < squeeze_rounds; ++i) {
			for(std::uint64_t r_i = 0; r_i < r; ++r_i) {
				hash_result.push_back((state >> r_i) & 0xff);
			}
			state = f(state);
		}

		return hash_result;
	}



	constexpr auto sponge(auto f, std::uint64_t r, std::uint64_t squeeze_rounds) {
		return [=] (const std::string & input) {
			return squeeze(absorb(input, f, r), f, r, squeeze_rounds);
		};
	}
}









void run(auto & hash){
	const auto str1 = "hello world";
	const auto str2 = "hallo worhd";
	const auto hash_value_1 = hash(str1); 
	const auto hash_value_2 = hash(str2); 
	std::cout << "  " << str1 << " => " << hex(hash_value_1) << "\n";
	std::cout << "  " << str2 << " => " << hex(hash_value_2) << "\n";
}



void run_xor_hash_collision() {
	constexpr auto hash = merkle_damgard_construction(
		0x0f0f0f0f0f0f0f0f,
		std::bit_xor{}
	);

	std::cout << "XOR-Hash (with Collision!!!)\n";
	run(hash);
}



void run_hash1() {
	constexpr auto hash = merkle_damgard_construction(
		0x0f0f0f0f0f0f0f0f,
		[] (const auto & l, const auto & r) {
			const auto a = l ^ r;
			const auto b = l + r;
			const auto c1 = l << 32;
			const auto c2 = r >> 32;
			const auto c = c1 | c2 + a;
			return a ^ b ^ c;
		}
	);

	std::cout << "Hash1\n";
	run(hash);
}


constexpr auto sponge_f1 = [] (const std::uint64_t x) {
	const auto a = (x >> 8) ^ (x << 7);
	const auto b = (~a) << 3;
	const auto c = 0x43bdef7290cce; 
	const auto d = (x >> 9) ^ c;
	const auto e = 0xabcdef0123456789; 
	return a ^ b ^ (c ^ d) << 1 ^ d ^ (x >> 42); 
};


void sponge_hash1() {
	constexpr auto hash = sponge::sponge(sponge_f1, 7, 1);
	std::cout << "Sponge Hash 1\n";
	run(hash);
}


void sponge_hash2() {
	constexpr auto hash = sponge::sponge(sponge_f1, 6, 2);
	std::cout << "Sponge Hash 1\n";
	run(hash);
}


int main() {
	run_xor_hash_collision();
	run_hash1();
	sponge_hash1();
	sponge_hash2();
	return 0;
}
