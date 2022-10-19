#include "feistel.hxx"


template<std::unsigned_integral T>
T f(T key, T x) {
	return key ^ x;
}


int main() {
	std::array<std::uint8_t,2> keys {0b0101, 0b1101};
	const std::uint8_t orignal = 0b01101001;
	const auto encrypted = feistel::encrypt<std::uint8_t>(orignal, f<std::uint8_t>, keys);
	const auto decrypted = feistel::decrypt<std::uint8_t>(encrypted, f<std::uint8_t>, keys);


	std::cout 
		<< "Original: "  << std::bitset<8>(orignal) << "\n"
		<< "Encrypted: " << std::bitset<8>(encrypted) << "\n"
		<< "Decrypted: " << std::bitset<8>(decrypted) << "\n"
		<< "\n";
	return 0;
}
