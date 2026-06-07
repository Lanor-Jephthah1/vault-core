import os
import sys
import webbrowser
import subprocess
import time

def launch_vaultcore():
    # Use the directory where launcher.py resides
    vaultcore_dir = os.path.dirname(os.path.abspath(__file__))
    server_script = "server.py"
    port = 8000
    url = f"http://localhost:{port}"

    # Change current working directory to vaultcore_dir
    os.chdir(vaultcore_dir)

    print("========================================")
    print("      VAULTCORE SECURE SERVER           ")
    print("========================================")
    print("\nStarting local environment...")
    
    # Start the web browser
    webbrowser.open(url)

    # Start the python server and keep it running in the terminal
    try:
        subprocess.run([sys.executable, server_script])
    except KeyboardInterrupt:
        print("\nStopping VaultCore server...")

if __name__ == "__main__":
    launch_vaultcore()
