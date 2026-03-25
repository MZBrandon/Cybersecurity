# Importing the regular expressions library
import re
# Defines password
def check_password(password):
    # Score counts how many rules the password passes out of 5
    score = 0
    feedback = []
    # Using the len to count the characters 
    # Using the score plus 1 if it passes otherwise feedback will be given
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    # Checks for one uppercase 
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add an uppercase letter")
    # Checks for one lowercase
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add a lowercase letter")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add a number")

    if re.search(r'[!@#$%^&*_-]', password):
        score += 1
    else:
        feedback.append("Add a special character (!@#$%^&*_-)")
    # Score determines what the output is from 0-5
    levels = {1: "Very Weak", 2: "Weak", 3: "Fair", 4: "Strong", 5: "Very Strong"}
    strength = levels.get(score, "Very Weak")
    # Prints the strength rating
    print(f"Strength: {strength} ({score}/5)")
    if feedback:
        print("Tips:", ", ".join(feedback))
# Input waits for the user to enter a password
password = input("Enter a password to check: ")
check_password(password)
