#include <iostream>
#include <string>
#include <cstring>
#include <limits>

// Function to encrypt the text with a simple way
// This function just shift per part of it such as 
// lower case, upper case, number, and symbols
std::string simpleEncrypt(std::string &text, int shift){
    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++){
        // Symbols { | } ~
        if(text[i] >= '{' && text[i] <= '~')
            text[i] = char((text[i] + shift - '{') % 4 + '{');
        // Lowercase letters a-z
        else if( text[i] >= 'a' && text[i] <= 'z' )
            text[i] = char((text[i] + shift - 'a') % 26 + 'a');
        // Symbols ^ _ `
        else if(text[i] >= '^' && text[i] <= '`')
            text[i] = char((text[i] + shift - '^') % 3 + '^');
        // Uppercase letters A-Z
        else if( text[i] >= 'A' && text[i] <= 'Z' )
            text[i] = char((text[i] + shift - 'A') % 26 + 'A');
        // Symbols : ; < = > ? @
        else if(text[i] >= ':' && text[i] <= '@')
            text[i] = char((text[i] + shift - ':') % 7 + ':');
        // Numbers 0-9
        else if( text[i] >= '0' && text[i] <= '9')
            text[i] = char((text[i] + shift - '0') % 10 + '0');
        // Symbols ' ' ! " # $ % & ' ( ) * + , - . /
        else if(text[i] >= ' ' && text[i] <= '/')
            text[i] = char((text[i] + shift - ' ') % 16 + ' ');
        
    }
    return text;
}

// Function to decrypt the text with a simple way
std::string simpleDecrypt(std::string &text, int shift){
    for(int i = 0; i < text.length(); i++){
        // Symbols { | } ~
        if(text[i] >= '{' && text[i] <= '~')
            text[i] = char((text[i] - (shift % 4) - '{' + 4) % 4 + '{');
        // Lowercase letters a-z
        else if(text[i] >= 'a' && text[i] <= 'z' )
            text[i] = char((text[i] - (shift % 26) - 'a' + 26) % 26 + 'a');
        // Symbols ^ _ `
        else if(text[i] >= '^' && text[i] <= '`')
            text[i] = char((text[i] - (shift % 3) - '^' + 3) % 3 + '^');
        // Uppercase letters A-Z
        else if(text[i] >= 'A' && text[i] <= 'Z' )
            text[i] = char((text[i] - (shift % 26) - 'A' + 26) % 26 + 'A');
        // Symbols : ; < = > ? @
        else if(text[i] >= ':' && text[i] <= '@')
            text[i] = char((text[i] - (shift % 7) - ':' + 7) % 7 + ':');
        // Numbers 0-9
        else if(text[i] >= '0' && text[i] <= '9')
            text[i] = char((text[i] - (shift % 10) - '0' + 10) % 10 + '0');
        // Symbols ' ' ! " # $ % & ' ( ) * + , - . /
        else if(text[i] >= ' ' && text[i] <= '/')
            text[i] = char((text[i] - (shift % 16) - ' ' + 16) % 16 + ' ');
        
    }
     return text;
}

// Function to decrypt the text with a complex way
// This function shifts all of the characters from 32 to 126
std::string encrypt(std::string text, int shift){

    shift = shift % 95;
    // Loop through the array and shift the characters by the shift value.
    for(int i = 0; i < text.length(); i++)
        // from 32 to 126 is symbols, numbers, and letters
        if(text[i] >= ' ' && text[i] <= '~' )
            if(text[i] + shift > 126)
                text[i] = char((text[i] + shift) % 126 + 31);
            else if(text[i] + shift < 32)
                text[i] = char((text[i] + shift) % 126 + 95);
            else
                text[i] = char((text[i] + shift - 32) % 96 + 32);
        
    return text;
}

std::string decrypt(std::string &text, int shift){
    return encrypt(text, -shift);
}

// Main function to handle user input and output.
int main(){
    
    int option, shift;
    std::string text;
    
    while(true){
        // system("cls");
        std::cout << "=============================\n";
        std::cout << "\tCaesar Cipher\n";
        std::cout << "=============================\n";
        std::cout << "1. Encrypt\n2. Decrypt\n";
        std::cout << "=============================\n";
        std::cout << "Option : "; std::cin >> option;
        if(option != 1 && option != 2){
            std::cout << "Invalid option !!" << std::endl;
            break;
        }
        
        // Clear the input buffer before taking input for the text
        std::cin.ignore();
        std::cout << "\nInput the text : "; std::getline(std::cin, text);
        
        std::cout << "Shift value : ";
        if (!(std::cin >> shift)) {
            // Input is not a valid integer
            std::cout << "Invalid input !!" << std::endl;
            // Clear the error state of cin
            std::cin.clear();
            // Discard invalid input
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            break;
        }
        
        // Perform the selected operation on the text and shift value.
        if(option == 1){
                std::cout << "\nEncrypt Text : " << encrypt(text, shift) << std::endl;
                std::cout << "Simple Encryption : " << simpleEncrypt(text, shift) << std::endl << std::endl;
        }else{
            std::cout << "\nDecrypt Text : " << decrypt(text, shift) << std::endl;
            std::cout << "Simple Decryption : " << simpleDecrypt(text, shift) << std::endl << std::endl;
        }

        std::cout << "Do you want to continue ? (y/n) : "; std::cin >> text;
        if(!(text == "y" || text == "Y"))
            break;
            
    }

    return 0;
}