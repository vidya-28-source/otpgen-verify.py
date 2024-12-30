import pyotp
import tkinter as tk
from tkinter import messagebox
import time  # For tracking the expiration time

# Step 1: Generate a secret key for the user
def generate_secret_key():
    # This generates a random secret key for the user (Base32 encoding)
    secret = pyotp.random_base32()
    return secret

# Step 2: Generate OTP from the secret key and store the generation time
def generate_otp(secret_key):
    totp = pyotp.TOTP(secret_key)  # Create a TOTP object using the secret key
    otp = totp.now()  # Generate OTP
    return otp, time.time()  # Return OTP and the current time

# Step 3: Verify OTP entered by the user and check if it's expired
def verify_otp(secret_key, entered_otp, otp_time_generated):
    totp = pyotp.TOTP(secret_key)  # Create a TOTP object using the secret key
    if time.time() - otp_time_generated > 60:  # Check if 60 seconds have passed
        return False, "OTP has expired!"  # OTP has expired
    if totp.verify(entered_otp):  # Verifies the OTP (returns True if valid)
        return True, "OTP is valid!"  # OTP is valid
    else:
        return False, "Invalid OTP! Try again."  # OTP is invalid

# Step 4: Function to handle OTP generation and display it in the window
def on_generate():
    global secret_key, otp_time_generated, timer_running  # Declare global variables
    secret_key = generate_secret_key()
    otp, otp_time_generated = generate_otp(secret_key)
    label_otp.config(text=f"Generated OTP: {otp}")
    label_otp.pack()

    # Start the countdown timer
    timer_running = True
    update_timer()  # Update the timer display immediately

# Step 5: Function to handle OTP verification
def on_verify():
    global timer_running
    entered_otp = entry_otp.get()  # Get the OTP entered by the user
    valid, message = verify_otp(secret_key, entered_otp, otp_time_generated)
    if valid:
        messagebox.showinfo("Success", message)  # Show success message
        timer_running = False  # Stop the timer after successful verification
    else:
        messagebox.showerror("Error", message)  # Show error message

# Step 6: Function to update the countdown timer
def update_timer():
    global timer_running  # Make sure to reference the global variable
    if timer_running:
        time_left = int(60 - (time.time() - otp_time_generated))  # Calculate time left
        if time_left > 0:
            label_timer.config(text=f"Time left: {time_left} seconds")
            label_timer.after(1000, update_timer)  # Call update_timer again after 1 second
        else:
            label_timer.config(text="OTP has expired!")
            timer_running = False  # Stop the timer once it expires

# Step 7: Create the main GUI window
root = tk.Tk()
root.title("OTP Generator and Verifier")

# GUI Components
label_instruction = tk.Label(root, text="Click 'Generate OTP' to generate an OTP.")
label_instruction.pack(pady=10)

button_generate = tk.Button(root, text="Generate OTP", command=on_generate)
button_generate.pack(pady=10)

label_otp = tk.Label(root, text="", font=("Arial", 16))

label_enter_otp = tk.Label(root, text="Enter OTP to Verify:")
label_enter_otp.pack(pady=10)

entry_otp = tk.Entry(root, font=("Arial", 16))
entry_otp.pack(pady=10)

button_verify = tk.Button(root, text="Verify OTP", command=on_verify)
button_verify.pack(pady=10)

# Label for displaying the countdown timer
label_timer = tk.Label(root, text="Time left: 60 seconds", font=("Arial", 14))
label_timer.pack(pady=10)

# Initialize the global variable to track whether the timer is running
timer_running = False
otp_time_generated = 0  # Initialize the OTP generation time

# Start the GUI event loop
root.mainloop()
