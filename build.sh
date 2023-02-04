cmake . -D CMAKE_CXX_COMPILER=clang++ -B ./build
cd build
make
cd ..

mkdir ./bin
mv ./build/bin/feistel ./bin/feistel
mv ./build/bin/rsa ./bin/rsa
mv ./build/bin/aes ./bin/aes
mv ./build/bin/modes ./bin/modes
mv ./build/bin/hash ./bin/hash
mv ./build/bin/diffie_hellman ./bin/diffie_hellman