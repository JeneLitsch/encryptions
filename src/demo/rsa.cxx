#include "crypto/rsa.hxx"
#include <iostream>

int main() {
	const auto p = 7;
	const auto q = 11;
	const auto [pri_key, pub_key] = rsa::generate_keys<std::uint64_t>(p, q);
	const auto original = 42;
	const auto encrypted = rsa::encrypt<std::uint64_t>(original, pub_key);
	const auto decrypted = rsa::decrypt<std::uint64_t>(encrypted, pri_key);

	std::cout << "===Private Key===\n";
	std::cout << "p: " << pri_key.p << "\n";
	std::cout << "q: " << pri_key.q << "\n";
	std::cout << "d: " << pri_key.d << "\n";
	std::cout << "\n";

	std::cout << "===Public Key===\n";
	std::cout << "n: " << pub_key.n << "\n";
	std::cout << "e: " << pub_key.e << "\n";
	std::cout << "\n";

	std::cout << "===Data===\n";
	std::cout << "Original:  " << original << "\n";
	std::cout << "Encrypted: " << encrypted << "\n";
	std::cout << "Decrypted: " << decrypted << "\n";
	std::cout << "\n";
	return 0;
}
