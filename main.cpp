#include <iostream>
#include <string>
#include <cstring>


std::string encryption(std::string text, int shift){
    // Convert the string to a character array for easier manipulation.
    char arrayText[text.length()];
    strcpy(arrayText, text.c_str());

    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++){
        // from 32 to 126 is symbols, numbers, and letters
        if( int(arrayText[i]) >= 32 && int(arrayText[i]) <= 126 ){
            arrayText[i] = char((int(arrayText[i]) + shift - 32) % 95 + 32);
        }
        // from 33 to 47, 58 to 64, 94 to 96, and 123 to 126 is symbol 
        // from 48 to 57 is number
        // if( int(arrayText[i]) > 47 && int(arrayText[i]) < 58){
        //     arrayText[i] = char((int(arrayText[i]) + shift - 48) % 10 + 48);
        // }
        // // from 65 to 90 is upper case
        // if( int(arrayText[i]) > 64 && int(arrayText[i]) < 91 ){
        //     arrayText[i] = char((int(arrayText[i]) + shift - 65) % 26 + 65);
        // }
        // // from 97 to 122 is lower case
        // if( int(arrayText[i]) > 96 && int(arrayText[i]) < 123 ){
        //     arrayText[i] = char((int(arrayText[i]) + shift - 97) % 26 + 97);
        // }
    }
    return arrayText;
}

std::string decryption(std::string text, int shift){
    return encryption(text, -shift);
}

int main(){

    std::string message;
    int shift;
    std::cout << "Input the text : "; std::cin >> message;
    std::cout << "Shift value : "; std::cin >> shift;

    std::string encryptMessage = encryption(message, shift);
    std::cout << "Encrypted : " << encryptMessage << std::endl;

    std::string decryptMessage = decryption(encryptMessage, shift);
    std::cout << "Decrypted : " << decryptMessage << std::endl;
}