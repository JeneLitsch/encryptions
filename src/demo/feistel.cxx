#include "crypto/feistel.hxx"

int main() {
	std::array<std::uint8_t,2> keys {0b0101, 0b1101};
	const std::uint8_t orignal = 0b10011100;
	const auto encrypted = feistel::encrypt<std::uint8_t>(orignal, feistel::f_xor<std::uint8_t>, keys);
	const auto decrypted = feistel::decrypt<std::uint8_t>(encrypted, feistel::f_xor<std::uint8_t>, keys);


	std::cout 
		<< "Original: "  << std::bitset<8>(orignal) << "\n"
		<< "Encrypted: " << std::bitset<8>(encrypted) << "\n"
		<< "Decrypted: " << std::bitset<8>(decrypted) << "\n"
		<< "\n";
	return 0;
}
