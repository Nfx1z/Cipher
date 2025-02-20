import os

def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_amount = 65 if char.isupper() else 97
            result += chr((ord(char) + shift - shift_amount) % 26 + shift_amount)
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
       
    text = input("Enter the text : ")
    # checking if text is not character
    if not text.isalpha():
        os.system('cls' if os.name == 'nt' else 'clear')    
        print("Text must contain only alphabetic characters!")
        continue

    shift = input("Shift : ")
    # checking if shift is a valid number
    if not shift.isdigit():
        os.system('cls' if os.name == 'nt' else 'clear')
        print("Shift must be a number!")
        continue

    # converting shift to integer if it's a string
    shift = int(shift)

    # performing encryption or decryption based on user's choice
    if option == '1':
        encrypted_text = encrypt(text, shift)
        print(f"Encrypted: {encrypted_text}")

    elif option == '2':
        decrypted_text = decrypt(text, shift)
        print(f"Decrypted: {decrypted_text}")
    
    # break if the choice is invalid
    else:
        print("Invalid option !")
        break

    # ask user to continue
    continue_input = input("\nDo you want to continue? (Y/N): ")
    
    # break the loop if user chooses to stop
    if continue_input.lower() != 'y':
        break

