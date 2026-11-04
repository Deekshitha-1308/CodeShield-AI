import pickle
import subprocess

password = "admin123"

def calculate_total(price, quantity):
    try:
        return price * quantity
    except:
        return 0

def run_user_command(user_input):
    # Demo-only vulnerable pattern: never do this with untrusted input.
    return subprocess.run(user_input, shell=True, capture_output=True)

def load_user_data(blob):
    return pickle.loads(blob)

def compare_names(name):
    if name is "admin":
        return True
    return False
