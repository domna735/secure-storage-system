import os
from client_functions import register, login, logout, reset_password, view_logs
from clientfile_handler import  share_file, upload_file_efficient, download_file_efficient, delete_file_efficient

def main():
    current_user = None  # Currently logged in user
    aes_key = None       # Current user's AES key

    while True:
        print("\n==== Secure Storage Client ====")

        if current_user:
            print(f"Logged in as: {current_user}")
            
            # ✅ Admin's Interface
            if current_user == "admin":
                print("1. View Logs")
                print("2. Logout")
                print("3. Exit")
                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    view_logs()

                elif choice == "2":
                    logout(current_user)
                    current_user, aes_key = None, None

                elif choice == "3":
                    print("Exited Successfully.")
                    break

                else:
                    print("Invalid choice. Please try again.")

            else:
                # ✅ Normal user's Interface
                print("1. Reset Password")
                print("2. Upload File")
                print("3. Download File")
                print("4. Delete File")
                print("5. Share File")
                print("6. Logout")
                print("7. Exit")

                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    reset_password(current_user)

                elif choice == "2":
                    filename = input("Enter filename to upload: ").strip()
                    #upload_file(current_user, filename, aes_key)  # 交给 upload_file 自行判断
                    upload_file_efficient(current_user, filename, aes_key)

                elif choice == "3":
                    #download_file(current_user, aes_key)
                    download_file_efficient(current_user, aes_key)

                elif choice == "4":
                    #delete_file(current_user)
                    delete_file_efficient(current_user)
                    
                elif choice == "5":
                    share_file(current_user)

                elif choice == "6":
                    logout(current_user)
                    current_user, aes_key = None, None

                elif choice == "7":
                    print("Exited program.")
                    break

                else:
                    print("Invalid choice. Please try again.")

        else:
            # ✅ Unlogged in screen
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                register()

            elif choice == "2":
                current_user, aes_key = login()
                if not current_user:
                    print("Login failed. Please try again.")

            elif choice == "3":
                print("Exiting program.")
                break

            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
