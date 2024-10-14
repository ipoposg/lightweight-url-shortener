from werkzeug.security import generate_password_hash

# Define the password to hash
password = "qwertyuiop"

# Generate the hash
hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

# Print the hashed password
print(f"Your hashed password is: {hashed_password}")