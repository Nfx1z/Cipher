#include <iostream>
#include <string>
#include <cstring>
#include <limits>

bool isLetter(std::string text){
    for(char ch : text)
        if(!isalpha(ch))
            return false;
    return true;
}

// Function to encrypt the text.
std::string encryption(std::string text, int shift){

    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++)
        // 97 is lower case, 65 is upper case
        (islower(text[i])) ? 
        text[i] = char((int(text[i]) + shift - 97) % 26 + 97) : 
        text[i] = char((int(text[i]) + shift - 65) % 26 + 65);

    return text;
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
        std::cout << "\n=============================\n";
        std::cout << "\tCaesar Cipher\n";
        std::cout << "=============================\n";
        std::cout << "1. Encrypt\n2. Decrypt\n";
        std::cout << "=============================\n";
        std::cout << "Option : "; std::cin >> option;
        
        if(option != 1 && option != 2){
            std::cout << "\tInvalid option\n"; 
            break;
        }
        // Clear the input buffer before taking input for the text
        std::cin.ignore();
        std::cout << "\nInput the text : "; std::getline(std::cin, text);
        if(!isLetter(text)){
            std::cout << "\tInvalid text\n"; 
            break;
        }
        std::cout << "Shift value : "; std::cin >> shift;
        if(!(shift > 0 && shift < 99999)){
            std::cout << "\tInvalid shift value\n"; 
            break;
        }

        if(option == 1)
            std::cout << "Encrypt Text : " << encryption(text, shift);
        if(option == 2)
            std::cout << "Decrypt Text : " << decryption(text, shift);
        std::cout << std::endl << std::endl;
    }

    return 0;
}