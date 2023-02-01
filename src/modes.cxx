#include <iostream>
#include <cstdint>
#include <vector>
#include "hexed.hxx"

namespace crypto {
	std::uint64_t xor_cipher(std::uint64_t key, std::uint64_t block) {
		return key ^ block;
	}


	std::uint64_t rot_cipher_e(std::uint64_t key, std::uint64_t block) {
		return block + key;
	}


	std::uint64_t rot_cipher_d(std::uint64_t key, std::uint64_t block) {
		return block - key;
	}



	inline std::vector<std::uint64_t> ecb(
		auto crypto, std::uint64_t key,
		const std::vector<std::uint64_t> & in) {
		std::vector<std::uint64_t> out;
		for(const auto block : in) {
			out.push_back(crypto(key, block));
		}
		return out;
	}



	inline std::vector<std::uint64_t> cbc_e(
		auto crypto, std::uint64_t key,
		std::uint64_t iv,
		const std::vector<std::uint64_t> & in) {
		
		std::uint64_t prev = iv;
		std::vector<std::uint64_t> out;
		for(const auto & block : in) {
			out.push_back(crypto(key, block ^ prev));
			prev = out.back();
		}

		return out;
	}



	inline std::vector<std::uint64_t> cbc_d(
		auto crypto, std::uint64_t key, std::uint64_t iv,
		const std::vector<std::uint64_t> & in) {
		
		std::uint64_t prev = iv;
		std::vector<std::uint64_t> out;
		for(const auto & block : in) {
			out.push_back(crypto(key, block) ^ prev);
			prev = block;
		}

		return out;
	}



	inline std::vector<std::uint64_t> ctr(
		auto crypto, std::uint64_t key, std::uint64_t iv,
		const std::vector<std::uint64_t> & in) {
		std::vector<std::uint64_t> out;
		for(std::size_t i = 0; i < std::size(in); ++i) {
			out.push_back(in[i] ^ crypto(key, iv + i));
		}
		return out;
	}
}



void run(
	std::string_view name,
	auto encrypt, auto decrypt,
	const std::vector<std::uint64_t> & plain,
	const std::uint64_t & key,
	const std::uint64_t & iv) {
	
	const auto cipher_ecb = crypto::ecb(encrypt, key, plain);
	const auto plain_ecb = crypto::ecb(decrypt, key, cipher_ecb);

	const auto cipher_cbc = crypto::cbc_e(encrypt, key, iv, plain);
	const auto plain_cbc = crypto::cbc_d(decrypt, key, iv, cipher_cbc); 

	const auto cipher_ctr = crypto::ctr(encrypt, key, iv, plain);
	const auto plain_ctr = crypto::ctr(encrypt, key, iv, cipher_ctr);

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
