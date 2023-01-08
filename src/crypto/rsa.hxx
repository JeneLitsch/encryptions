#pragma once
#include <cstdint>
#include <concepts>
#include <numeric>
#include <tuple>
#include <stdexcept>

namespace rsa {
	template<std::unsigned_integral Block>
	struct PublicKey {
		Block n;
		Block e;
	};



	template<std::unsigned_integral Block>
	struct PrivateKey {
		Block p;
		Block q;
		Block d;
	};



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



	template<std::unsigned_integral Block>
	Block phi(Block p, Block q) {
		return (q - 1) * (p - 1);
	}



	template<std::unsigned_integral Block>
	Block find_e(Block p, Block q) {
		const auto mod = phi(p,q);
		for(Block e = 2; e < mod; ++e) {
			if(std::gcd(mod, e) == 1) return e; 
		}
		throw std::runtime_error{"Cannot find e"};
	}



	template<std::unsigned_integral Block>
	Block find_d(Block p, Block q, Block e) {
		const auto mod = phi(p,q);
		for(Block d = 2; d < mod; ++d) {
			if(((e * d) % mod) == 1) return d; 
		}
		throw std::runtime_error{"Cannot find d"};
	}



	template<std::unsigned_integral Block>
	auto generate_keys(Block p, Block q) {

		const auto e = find_e(p, q);
		const auto d = find_d(p, q, e);
		const auto n = p * q;
		const PrivateKey<Block> pri_key { .p = p, .q = q, .d = d };
		const PublicKey<Block> pub_key { .n = n, .e = e };
		return std::make_tuple(pri_key, pub_key);
	}



	template<std::unsigned_integral Block>
	Block encrypt(Block plain, PublicKey<Block> key) {
		return repeated_squaring(plain, key.e, key.n);
	}



	template<std::unsigned_integral Block>
	Block decrypt(Block cipher, PrivateKey<Block> key) {
		return repeated_squaring(cipher, key.d, key.p * key.q);
	}
}