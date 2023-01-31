#include "crypto/modes.hxx"
#include <iostream>

template<typename T>
struct hexed {
	const T & value;
};

std::ostream & operator<<(std::ostream & out, const hexed<std::vector<std::uint64_t>> & hexed) {
	bool first = true;
	for(const auto & elem : hexed.value) {
		if(first) first = false;
		else out << ", ";
		out << "0x" << elem;
	}
	return out;
}


std::ostream & operator<<(std::ostream & out, const hexed<std::uint64_t> & hexed) {
	out << "0x" << hexed.value;
	return out;
}


template<typename T>
hexed<T> hex(const T & x) {
	return hexed<T>{
		.value = x
	};
}



void run(
	std::string_view name,
	auto encrypt, auto decrypt,
	const std::vector<std::uint64_t> & plain,
	const std::uint64_t & key,
	const std::uint64_t & iv) {
	
	const auto cipher_ecb = modes::ecb(encrypt, key, plain);
	const auto plain_ecb = modes::ecb(decrypt, key, cipher_ecb);

	const auto cipher_cbc = modes::cbc_e(encrypt, key, iv, plain);
	const auto plain_cbc = modes::cbc_d(decrypt, key, iv, cipher_cbc); 

	const auto cipher_ctr = modes::ctr(encrypt, key, iv, plain);
	const auto plain_ctr = modes::ctr(encrypt, key, iv, cipher_ctr);

	std::cout << "Encrypted " << name << "\n";
	std::cout << "  Cipher ECB: " << hex(cipher_ecb) << "\n";
	std::cout << "  Cipher CBC: " << hex(cipher_cbc) << "\n";
	std::cout << "  Cipher CTR: " << hex(cipher_ctr) << "\n";

	std::cout << "Decrypted " << name << "\n";
	std::cout << "  Plain ECB: " << hex(plain_ecb) << "\n";
	std::cout << "  Plain CBC: " << hex(plain_cbc) << "\n";
	std::cout << "  Plain CTR: " << hex(plain_ctr) << "\n";

	std::cout << "\n";
}


int main() {
	const std::uint64_t key = 0x123456890abcdef;
	const std::uint64_t iv  = 0xaabbccddeeff123;
	const std::vector<std::uint64_t> plain = {0x42, 0x1337, 0x1234, 0x42, 0x42};
	
	std::cout << std::hex;
	std::cout << "Parameters\n";
	std::cout << "  Key:        " << hex(key) << "\n";
	std::cout << "  Plain:      " << hex(plain) << "\n";
	std::cout << "  IV:         " << hex(iv) << "\n";
	std::cout << "\n";

	run("XOR", crypto::xor_cipher,   crypto::xor_cipher,   plain, key, iv);
	run("ROT", crypto::rot_cipher_e, crypto::rot_cipher_d, plain, key, iv);


	return 0;
}
