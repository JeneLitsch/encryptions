#include <string>
#include <vector>
#include <iostream>

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



constexpr auto xor_hash = merkle_damgard_construction(
	0x0f0f0f0f0f0f0f0f,
	std::bit_xor{}
);



constexpr auto hash1 = merkle_damgard_construction(
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



void run_xor_hash_collision() {
	std::cout << "XOR-Hash (with Collision!!!)\n";
	const auto str1 = "hello world";
	const auto str2 = "hallo worhd";
	const auto hash_value_1 = xor_hash(str1); 
	const auto hash_value_2 = xor_hash(str2); 
	std::cout << "  " << str1 << " => " << "0x" << std::hex << hash_value_1 << "\n";
	std::cout << "  " << str2 << " => " << "0x" << std::hex << hash_value_2 << "\n";
}



void run_hash1() {
	std::cout << "Hash1\n";
	const auto str1 = "hello world";
	const auto str2 = "hallo worhd";
	const auto hash_value_1 = hash1(str1); 
	const auto hash_value_2 = hash1(str2); 
	std::cout << "  " << str1 << " => " << "0x" << std::hex << hash_value_1 << "\n";
	std::cout << "  " << str2 << " => " << "0x" << std::hex << hash_value_2 << "\n";
}




int main() {
	run_xor_hash_collision();
	run_hash1();
	return 0;
}
