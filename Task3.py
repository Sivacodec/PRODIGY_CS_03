import re

def check_password_strength(password):
    # Define criteria for a strong password
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    special_char_error = re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password) is None

    # Check the strength of the password based on criteria
    if length_error:
        return "Your password should be at least 8 characters long."
    elif digit_error:
        return "Your password should contain at least one digit."
    elif uppercase_error:
        return "Your password should contain at least one uppercase letter."
    elif lowercase_error:
        return "Your password should contain at least one lowercase letter."
    elif special_char_error:
        return "Your password should contain at least one special character."
    else:
        return "Congratulations! Your password is strong."

def main():
    while True:
        password = input("Enter your password: ")
        if password.lower() == "exit":
            print("Goodbye!")
            break
        strength = check_password_strength(password)
        print(strength)

if __name__ == "__main__":
    main()
