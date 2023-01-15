#include "crypto/rsa.hxx"
#include <iostream>

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
