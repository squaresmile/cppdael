#include <string>
#include <vector>
#include <iostream>
#include "rijndael.h"

unsigned char cipher[] = { 51, 63, 127, 231, 101, 33, 105, 79, 232, 118, 136, 49, 62, 61, 162, 123, 67, 215, 9, 205, 91, 117, 184, 123, 154, 77, 140, 199, 241, 171, 238, 71, 158, 183, 34, 6, 3, 41, 139, 157, 5, 84, 105, 218, 47, 64, 226, 56, 66, 36, 51, 174, 140, 187, 193, 234, 141, 53, 223, 16, 29, 80, 96, 84, 172, 150, 156, 237, 229, 192, 95, 191, 186, 176, 138, 110, 5, 149, 56, 113, 157, 71, 42, 196, 56, 154, 228, 70, 115, 21, 46, 44, 182, 244, 31, 8, 21, 59, 216, 123, 27, 62, 86, 158, 170, 66, 14, 99, 98, 214, 78, 144, 63, 202, 127, 192, 74, 15, 53, 253, 159, 229, 85, 84, 14, 151, 177, 122, 124, 110, 24, 49, 125, 88, 167, 118, 123, 150, 73, 163, 173, 232, 78, 212, 141, 97, 3, 139, 136, 231, 189, 255, 66, 0, 60, 5, 154, 193, 213, 193 };
std::vector<unsigned char> iv = { 174, 21, 159, 13, 174, 92, 13, 69, 101, 116, 21, 163, 165, 164, 149, 66, 88, 192, 98, 176, 27, 145, 65, 22, 188, 110, 175, 163, 14, 215, 11, 34 };

std::string _key = "osu!-scoreburgr---------20211103";

int main() {
    std::string cipher_str(cipher, cipher + sizeof cipher / sizeof cipher[0]);
    std::string iv_str(iv.begin(), iv.end());

    const std::string aes = decrypt_string(cipher_str, _key, iv_str);

    std::cout << aes << std::endl;

    return 0;
}
