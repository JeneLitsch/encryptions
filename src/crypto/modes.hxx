#pragma once
#include <cstdint>
#include <vector>

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
}

namespace modes {
	
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