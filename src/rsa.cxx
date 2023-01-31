#include <cstdint>
#include <concepts>
#include <numeric>
#include <tuple>
#include <stdexcept>
#include <optional>
#include <iostream>

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



	auto modulus(auto a, auto b) {
		return (a % b + b) % b;
	}


	template<std::signed_integral T>
	std::pair<T, T> euklid_rec(T a, T b) {
		if(b == 0) return {1,0};
		T divisor = a / b;
		T remainder = a % b;
		auto [s, t] = euklid_rec(b, remainder);
		return { t, s - (a / b) * t };
	}


	template<std::unsigned_integral Block>
	std::pair<Block, Block> euklid(Block a, Block b, Block n) {
		using S = std::make_signed_t<Block>;
		// return euklid_rec<S>(a, b);
		const auto [s, t] = euklid_rec<S>(a, b);
		return {
			s < 0 ? static_cast<S>(n) + s : s,
			t < 0 ? static_cast<S>(n) + t : t,
		};
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
	auto generate_keys(Block p, Block q, std::optional<Block> e_suggest = std::nullopt) {

		const auto e = e_suggest.value_or(find_e(p, q));
		const auto n = p * q;
		auto [d, x] = euklid(e, phi(p,q), phi(p,q));
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


int main() {
	std::uint64_t p = 7;
	std::uint64_t q = 11;
	std::uint64_t e = 11;


	std::cout << "p = ";
	std::cin >> p;
	std::cout << "q = ";
	std::cin >> q;
	std::cout << "e = ";
	std::cin >> e;
	std::cout << "\n";

	const auto [pri_key, pub_key] = rsa::generate_keys<std::uint64_t>(p, q, e);

	std::cout << "===Private Key===\n";
	std::cout << "p: " << static_cast<std::int64_t>(pri_key.p) << "\n";
	std::cout << "q: " << static_cast<std::int64_t>(pri_key.q) << "\n";
	std::cout << "d: " << static_cast<std::int64_t>(pri_key.d) << "\n";
	std::cout << "\n";

	std::cout << "===Public Key===\n";
	std::cout << "n: " << static_cast<std::int64_t>(pub_key.n) << "\n";
	std::cout << "e: " << static_cast<std::int64_t>(pub_key.e) << "\n";
	std::cout << "\n";

	while(true) {
		std::uint64_t original = 42;
		std::string mode = "";
		
		std::cout << "plaintext(number) = ";
		std::cin >> original;
		std::cout << "mode(e/d) = ";
		std::cin >> mode;

		if(mode == "e") {
			const auto encrypted = rsa::encrypt<std::uint64_t>(original, pub_key);
			std::cout << "Encrypted: " << "e(" << original << ") = " << encrypted << "\n";

		}
		if(mode == "d") {
			const auto decrypted = rsa::decrypt<std::uint64_t>(original, pri_key);
			std::cout << "Decrypted: " << "d(" << original << ") = " << decrypted << "\n";
		}
		std::cout << "\n";
		std::cin.clear();
		std::cin.ignore(100000, '\n');
	}

	return 0;
}
