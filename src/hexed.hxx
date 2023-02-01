#pragma once
#include <iostream>
#include <vector>

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


template<std::integral T>
std::ostream & operator<<(std::ostream & out, const hexed<std::vector<T>> & hexed) {
	bool first = true;
	out << std::hex;
	for(const auto & elem : hexed.value) {
		if(first) first = false;
		else out << ", ";
		out << "0x" << static_cast<std::uint64_t>(elem);
	}
	return out;
}


std::ostream & operator<<(std::ostream & out, const hexed<std::uint64_t> & hexed) {
	out << std::hex << "0x" << static_cast<std::uint64_t>(hexed.value);
	return out;
}


template<typename T>
hexed<T> hex(const T & x) {
	return hexed<T>{
		.value = x
	};
}