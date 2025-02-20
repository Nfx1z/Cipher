#include <iostream>
#include <string>
#include <cstring>

// Function to encrypt the text with a simple way
// This function just shift per part of it such as 
// lower case, upper case, number, and symbols
std::string simpleEncrypt(std::string text, int shift){
    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++){
        // from 123 to 126 is symbol
        if(int(text[i]) > 122 && int(text[i]) < 127)
            text[i] = char((int(text[i]) + shift - 123) % 4 + 123);
        // from 97 to 122 is lower case
        if( int(text[i]) > 96 && int(text[i]) < 123 )
            text[i] = char((int(text[i]) + shift - 97) % 26 + 97);
        // from 94 to 96 is symbol
        if(int(text[i]) > 93 && int(text[i]) < 97)
            text[i] = char((int(text[i]) + shift - 94) % 3 + 94);
        // from 65 to 90 is upper case
        if( int(text[i]) > 64 && int(text[i]) < 91 )
            text[i] = char((int(text[i]) + shift - 65) % 26 + 65);
        // from 58 to 64 is symbol
        if(int(text[i]) > 57 && int(text[i]) < 65)
            text[i] = char((int(text[i]) + shift - 58) % 6 + 58);
        // from 48 to 57 is number
        if( int(text[i]) > 47 && int(text[i]) < 58)
            text[i] = char((int(text[i]) + shift - 48) % 10 + 48);
        // from 33 to 47 is symbol
        if(int(text[i]) > 32 && int(text[i]) < 48)
            text[i] = char((int(text[i]) + shift - 33) % 15 + 33);
        
    }
    return text;
}

// Function to decrypt the text with a simple way
std::string simpleDecrypt(const std::string &text, int shift){
    return simpleEncrypt(text, -shift);
}

// Function to decrypt the text with a complex way
// This function shifts all of the characters from 32 to 126
std::string encrypt(std::string text, int shift){

    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++)
        // from 32 to 126 is symbols, numbers, and letters
        if( int(text[i]) >= 32 && int(text[i]) <= 126 )
            if(int(text[i]) + shift > 126)
                text[i] = char((int(text[i]) + shift) % 126 + 32);
            else if(int(text[i]) + shift < 33)
                text[i] = char((int(text[i]) + shift) % 126 + 94);
            else
                text[i] = char((int(text[i]) + shift - 33 ) % 95 + 33);
        
    return text;
}

std::string decrypt(std::string &text, int shift){
    return encrypt(text, -shift);
}

int main(){

    std::string message;
    int shift;
    for(int i = 0; i < 255; i++){
        std::cout << i << " : " << char(i) << std::endl;
    }
    std::cout << "Input the text : "; std::cin >> message;
    std::cout << "Shift value : "; std::cin >> shift;
    shift = shift % 94;

    std::string encryptMessage = encrypt(message, shift);
    std::cout << "Encrypted : " << encryptMessage << std::endl;

    std::string decryptMessage = decrypt(encryptMessage, shift);
    std::cout << "Decrypted : " << decryptMessage << std::endl << std::endl;

    std::string simpleEncryptMessage = simpleEncrypt(message, shift);
    std::cout << "Simple Encrypted : " << simpleEncryptMessage << std::endl;

    std::string simpleDecryptMessage = simpleDecrypt(simpleEncryptMessage, shift);
    std::cout << "Simple Decrypted : " << simpleDecryptMessage << std::endl;
}