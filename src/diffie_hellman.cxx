#include <cstdint>
#include <iostream>
#include <set>
#include "rep_square.hxx"

namespace crypto::dh {
	bool is_prime(std::uint64_t p) {
		for(std::uint64_t i = 2; i*i <= p; ++i) {
			if((p % i) == 0) return false;
		}
		return true;
	}


	bool is_generator(std::uint64_t g, std::uint64_t p) {
		if(!is_prime(g)) return false;
		std::set<std::uint64_t> s;
		for(std::uint64_t i = 0; i <= p-2; ++i) {
			s.insert(repeated_squaring(g, i, p));
		}
		for(std::uint64_t i = 1; i <= p-1; ++i) {
			if(!s.contains(i)) return false;
		}
		return true;
	}


	std::uint64_t find_g(std::uint64_t p) {
		for(std::uint64_t g = 1; g < p; ++g) {
			if(is_generator(g, p)) return g;
		}
		return 0;
	}


	std::uint64_t generate_part(std::uint64_t g, std::uint64_t x, std::uint64_t n) {
		return repeated_squaring(g, x, n);
	}


	std::uint64_t finalize(std::uint64_t part, std::uint64_t x, std::uint64_t n) {
		return repeated_squaring(part, x, n);
	}
}




int main(int argc, char const *argv[]) {
	const std::uint64_t n = 2131;
	const std::uint64_t g = crypto::dh::find_g(n);

	const std::uint64_t a = 12;
	const std::uint64_t b = 4;

	const std::uint64_t g_a = crypto::dh::generate_part(g, a, n);
	const std::uint64_t g_b = crypto::dh::generate_part(g, b, n);

	const std::uint64_t k_a = crypto::dh::generate_part(g_b, a, n);
	const std::uint64_t k_b = crypto::dh::generate_part(g_a, b, n);

	std::cout << "Diffie-Hellman KEX\n";
	std::cout << "n:   " << n << "\n";
	std::cout << "g:   " << g << "\n";
	std::cout << "a:   " << a << "\n";
	std::cout << "b:   " << b << "\n";
	std::cout << "g^a: " << g_a << "\n";
	std::cout << "g^b: " << g_b << "\n";
	std::cout << "k_a: " << k_a << "\n";
	std::cout << "k_b: " << k_b << "\n";
}
