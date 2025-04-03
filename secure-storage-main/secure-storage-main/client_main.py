import os
from client_functions import register, login, change_password, view_logs
from clientfile_handler import  share_file,upload_file_efficient, download_file_efficient, delete_file_efficient

def main():
    current_user = None  # 当前登录用户
    aes_key = None       # 当前用户 AES 密钥

    while True:
        print("\n==== Secure Storage Client ====")

        if current_user:
            print(f"Logged in as: {current_user}")
            
            # ✅ 管理员界面
            if current_user == "admin":
                print("1. View Logs")
                print("2. Logout")
                print("3. Exit")
                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    view_logs()

                elif choice == "2":
                    print("Logging out...")
                    current_user, aes_key = None, None

                elif choice == "3":
                    print("Exiting program.")
                    break

                else:
                    print("Invalid choice. Please try again.")

            else:
                # ✅ 普通用户界面
                print("1. Change Password")
                print("2. Upload File")
                print("3. Download File")
                print("4. Delete File")
                print("5. Share File")
                print("6. Logout")
                print("7. Exit")

                choice = input("Enter your choice: ").strip()

                if choice == "1":
                    change_password(current_user)

                elif choice == "2":
                    filename = input("Enter filename to upload: ").strip()
                    #upload_file(current_user, filename, aes_key)  # 交给 upload_file 自行判
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
                    print(f"Logging out {current_user}...")
                    current_user, aes_key = None, None

                elif choice == "7":
                    print("Exiting program.")
                    break

                else:
                    print("Invalid choice. Please try again.")

        else:
            # ✅ 未登录界面
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
