"""
Caesar Cipher Encryption/Decryption
From ascii table 32 - 126

To encrypt or decyprt a message, enter the message and a positive shift value.

there are two ways  to encrypt or decrypt a message:
1. simple encryption algorithm ( 32 - 47, 48 - 57, 58 - 64, 91 - 96, 123 - 126 )
2. encryption from ascii table 32 - 126 ( shift all values )
"""

import os

# Function to encrypt a message using the simple encryption algorithm
def simpleEncrypt(text, shift):
    result = ""
    for char in text:
        if '{' <= char <= '~':  # Symbols { | } ~
            result += chr((ord(char) + shift - 123) % 4 + 123)
        elif 'a' <= char <= 'z':  # Lowercase letters a-z
            result += chr((ord(char) + shift - 97) % 26 + 97)
        elif '[' <= char <= '`':  # Symbols [ \ ] ^ _ `
            result += chr((ord(char) + shift - 91) % 6 + 91)
        elif 'A' <= char <= 'Z':  # Uppercase letters A-Z
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif ':' <= char <= '@':  # Symbols : ; < = > ? @
            result += chr((ord(char) + shift - 58) % 7 + 58)
        elif '0' <= char <= '9':  # Numbers 0-9
            result += chr((ord(char) + shift - 48) % 10 + 48)
        elif ' ' <= char <= '/':  # Symbols ' ' ! " # $ % & ' ( ) * + , - . /
            result += chr((ord(char) + shift - 32) % 16 + 32)

    return result

def simpleDecrypt(text, shift):
    return simpleEncrypt(text, -shift)

# Function to encrypt text from ASCII table 32 - 126
def encrypt(text, shift):
    shift = shift % 95
    result = ""
    for char in text:
        if(ord(char) + shift > 126):
            result += chr((ord(char) + shift) % 126 + 31)
        elif(ord(char) + shift < 32):
            result += chr((ord(char) + shift - 32) % 127)
        else:
            result += chr(ord(char) + shift)
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

# clear the terminal
os.system('cls' if os.name == 'nt' else 'clear')
    
# infinite loop for continuous input
while(True):

    print(f"\nCaesar Cipher Encryption/Decryption")
    print("--------------------------------")
    print("1. Encrypt")
    print("2. Decrypt")
    print("--------------------------------")
    # user's choice for encryption/decryption
    option = input("Option : ")
    if(option != '1' and option != '2'):
        print("Invalid option !")
        break
    
    # getting user's input for text and shift
    text = input("Enter the text : ")
    shift = input("Shift : ")
    # checking if shift is a valid number
    if not shift.isdigit():
        os.system('cls' if os.name == 'nt' else 'clear')
        print("Shift must be a number!\n")
        continue

    # converting shift to integer if it's a string
    shift = int(shift)

    # performing encryption or decryption based on user's choice
    if option == '1':
        print(f"Encrypted: {encrypt(text, shift)}")
        print(f"Simple Encrypted: {simpleEncrypt(text, shift)}")

    elif option == '2':
        print(f"Decrypted: {encrypt(text, shift)}")
        print(f"Simple Decrypted: {simpleDecrypt(text, shift)}")

    # ask user to continue
    continue_input = input("\nDo you want to continue? (Y/N): ")
    
    # break the loop if user chooses to stop
    if continue_input.lower() != 'y':
        break

