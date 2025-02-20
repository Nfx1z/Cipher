#include <iostream>
#include <string>
#include <cstring>

// Function to encrypt the text.
std::string encryption(std::string text, int shift){
    int shiftAmount = 0;
    // Convert the string to a character array for easier manipulation.
    char arrayText[text.length()];
    strcpy(arrayText, text.c_str());

    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++){
        // 97 is lower case, 65 is upper case
        (islower(arrayText[i])) ? shiftAmount = 97 : shiftAmount = 65;
        arrayText[i] = char((int(arrayText[i]) + shift - shiftAmount) % 26 + shiftAmount);
    }

    return arrayText;
};

// Function to decrypt the text.
std::string decryption(std::string text, int shift){
    return encryption(text, -shift);
};

// Main function to handle user input and output.
int main(){
    
    int option, shift;
    std::string text;
    
    system("cls");
    while(true){
        std::cout << "1. Encrypt\n2. Decrypt\n";
        std::cin >> option;
        
        if(option != 1 && option != 2){
            std::cout << "Invalid option\n";
            continue;
        }else if(option == 1){
            std::cout << "Input the text : "; std::cin >> text;
            std::cout << "Shift value : "; std::cin >> shift;
            std::cout << "Encrypt Text : " << encryption(text, shift) << std::endl;
        }else if(option == 2){
            std::cout << "Input the text : "; std::cin >> text;
            std::cout << "Shift value : "; std::cin >> shift;
            std::cout << "Decrypt Text : " << decryption(text, shift) << std::endl;
        }
    }

    return 0;
}