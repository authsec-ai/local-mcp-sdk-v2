import os
import json
import platform
import subprocess
import sys
from pathlib import Path
from shutil import which

ROOT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
PYPROJECT_FILE = ROOT_DIR / "pyproject.toml"

def check_uv():
    if which("uv") is None:
        print("[!] 'uv' not found. Installing via pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "uv"])
        except subprocess.CalledProcessError:
            print("[x] Failed to install 'uv'. Please install it manually.")
            sys.exit(1)
    else:
        print("[+] 'uv' is already installed.")

def create_pyproject_if_missing():
    if PYPROJECT_FILE.exists():
        print("[+] pyproject.toml already exists.")
        return

    print("[+] Creating pyproject.toml with default dependencies...")
    content = """[project]
name = "mcp-server-demo"
version = "0.1.0"
description = "Add your description here"
readme = "README.md"
requires-python = ">=3.13"
dependencies = [
    "aiohttp>=3.12.13",
    "asyncpg>=0.30.0",
    "mcp[cli]>=1.10.0"
]
"""
    PYPROJECT_FILE.write_text(content.strip() + "\n")

def install_dependencies():
    print("[+] Installing dependencies globally using uv with --system...")
    try:
        subprocess.check_call(["uv", "pip", "install", "-r", str(PYPROJECT_FILE), "--system"])
    except subprocess.CalledProcessError as e:
        print(f"[x] Dependency installation failed: {e}")
        sys.exit(1)

def ensure_scripts_folder():
    SCRIPTS_DIR.mkdir(exist_ok=True)

    default_scripts = {
        "setup_windows.bat": "@echo off\nREM Windows setup script\n",
        "setup_linux.sh": "#!/bin/bash\n# Linux setup script\n",
        "setup_macos.sh": "#!/bin/bash\n# macOS setup script\n"
    }

    for filename, content in default_scripts.items():
        script_path = SCRIPTS_DIR / filename
        if not script_path.exists():
            print(f"[+] Creating default script: {script_path}")
            script_path.write_text(content)
            if script_path.suffix == ".sh":
                script_path.chmod(0o755)

def run_os_script():
    system = platform.system()
    script_map = {
        "Windows": "setup_windows.bat",
        "Linux": "setup_linux.sh",
        "Darwin": "setup_macos.sh"
    }

    script_name = script_map.get(system)
    if not script_name:
        print("[x] Unsupported OS.")
        return

    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        print(f"[!] Script not found: {script_path}")
        return

    print(f"[+] Running OS-specific setup: {script_path}")
    try:
        if system == "Windows":
            subprocess.check_call([str(script_path)], shell=True)
        else:
            subprocess.check_call(["bash", str(script_path)])
    except subprocess.CalledProcessError as e:
        print(f"[x] Failed to run setup script: {e}")
        sys.exit(1)

def prompt_connection_string():
    print("[*] Please enter your Postgres connection string.")
    print("    Format: postgresql://user:password@host:port/database")

    while True:
        conn_str = input("> ").strip()
        if conn_str:
            os.environ["POSTGRES_CONNECTION_STRING"] = conn_str
            return conn_str
        else:
            print("[!] Connection string cannot be empty. Please try again.")

def create_env_file(conn_str: str):
    env_path = ROOT_DIR / ".env"
    lines = [
        "ENV=development",
        "DEBUG=True",
        f"POSTGRES_CONNECTION_STRING={conn_str}"
    ]

    if not env_path.exists():
        print("[+] Creating .env file...")
        env_path.write_text("\n".join(lines) + "\n")
    else:
        print("[+] Updating existing .env file with new POSTGRES_CONNECTION_STRING...")
        with open(env_path, "r", encoding="utf-8") as f:
            existing_lines = f.readlines()

        # Remove old POSTGRES_CONNECTION_STRING lines if any
        existing_lines = [line for line in existing_lines if not line.startswith("POSTGRES_CONNECTION_STRING=")]
        existing_lines += [f"POSTGRES_CONNECTION_STRING={conn_str}\n"]

        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(existing_lines)

def get_claude_config_path():
    """
    Returns the path to the Claude Desktop config directory for the current platform.
    """
    system = platform.system()

    if system == "Windows":
        appdata = os.getenv("APPDATA")
        return Path(appdata) / "Claude" if appdata else None
    elif system == "Darwin":  # macOS
        return Path.home() / "Library/Application Support/Claude"
    elif system == "Linux":
        return Path.home() / ".config/Claude"
    else:
        return None

def update_claude_config(conn_str: str):
    """
    Updates the Claude Desktop config with a new MCP server entry using the given Postgres connection string.
    """
    print("[*] Checking for Claude Desktop config...")

    claude_dir = get_claude_config_path()
    if not claude_dir:
        print("[!] Unable to determine Claude config path for this OS. Skipping config update.")
        return

    config_file = claude_dir / "claude_desktop_config.json"

    if not claude_dir.exists():
        print("[!] Claude Desktop folder not found. Skipping config update.")
        return

    if not config_file.exists():
        print("[!] Config file not found. Creating a new one...")

    # Format the repo path in POSIX-style (important for JSON)
    repo_path = str(ROOT_DIR).replace("\\", "/")

    new_config = {
        "mcpServers": {
            "postgres": {
                "command": "uv",
                "args": [
                    "run",
                    "--directory",
                    repo_path,
                    "python",
                    "main.py"
                ],
                "env": {
                    "POSTGRES_CONNECTION_STRING": conn_str
                }
            }
        }
    }

    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(new_config, f, indent=2)
        print(f"[+] Updated Claude Desktop config at: {config_file}")
    except Exception as e:
        print(f"[x] Failed to update Claude config: {e}")

def setup_windows_venv():
    """
    For Windows: create a virtual environment and install mcp_oauth_sdk.
    """
    print("[+] Creating uv virtual environment...")
    try:
        subprocess.check_call(["uv", "venv"])
    except subprocess.CalledProcessError as e:
        print(f"[x] Failed to create uv venv: {e}")
        sys.exit(1)

    print("[+] Installing mcp_oauth_sdk...")

    try:
        subprocess.check_call(["uv", "pip", "install", "git+https://github.com/authsec-ai/mcp_oauth_sdk.git"])
    except subprocess.CalledProcessError as e:
        print(f"[x] Failed to install mcp_oauth_sdk: {e}")
        sys.exit(1)

def main():
    print("[*] Initializing project environment...")
    check_uv()
    create_pyproject_if_missing()
    ensure_scripts_folder()
    install_dependencies()
    run_os_script()
    conn_str = prompt_connection_string()
    create_env_file(conn_str)
    update_claude_config(conn_str)
    if platform.system() == "Windows":
        setup_windows_venv()

    print("\n[✔] Setup complete.")

if __name__ == "__main__":
    main()