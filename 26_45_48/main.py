
from encryption import encrypt_file
from decryption import decrypt_file
from cryptography.exceptions import InvalidTag


def main():

    while True:

        print("\n================================")
        print("   SECURE FILE ENCRYPTION")
        print("================================")
        print("1. Encrypt a File")
        print("2. Decrypt a File")
        print("3. Exit")
        print("================================")

        choice = input("Enter your choice: ")

        # Encryption
        if choice == "1":

            input_file = input("Enter input filename: ")
            output_file = input("Enter output filename: ")

            try:
                encrypt_file(input_file, output_file)

            except Exception as e:
                print("Encryption failed:", e)

        # Decryption
        elif choice == "2":

            input_file = input("Enter encrypted filename: ")
            output_file = input("Enter output filename: ")

            try:
                decrypt_file(input_file, output_file)

            except InvalidTag:
                print("Decryption failed!")
                print("Incorrect key or encrypted data modified.")

            except Exception as e:
                print("Decryption failed:", e)

        # Exit
        elif choice == "3":
            print("Exiting Secure File Encryption System...")
            break

        else:
            print("Invalid choice! Please try again.")


if __name__ == "__main__":
    main()
