"""Simple Flask app with intentional security issues for testing."""

from flask import Flask, request
import subprocess
import os

app = Flask(__name__)

# Allowlist of safe commands that can be executed via the /run endpoint.
# Keys are values accepted from the "cmd" query parameter; values are argument lists.
ALLOWED_COMMANDS = {
    "hello": ["echo", "hello"],
    "date": ["date"],
}

@app.route("/")
def index():
    return "Hello, World!"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # Intentional: SQL-like string interpolation (CodeQL should flag)
    result = f"SELECT * FROM items WHERE name = '{query}'"
    return result


@app.route("/run")
def run_command():
    cmd_key = request.args.get("cmd", "hello")
    cmd = ALLOWED_COMMANDS.get(cmd_key)
    if cmd is None:
        return "Unsupported command", 400
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5)
        return output.decode()
    except FileNotFoundError:
        return "Configured command executable not found on server.", 500
    except subprocess.TimeoutExpired:
        return "Command execution timed out.", 504
    except subprocess.CalledProcessError as e:
        return f"Command '{cmd_key}' failed with exit code {e.returncode}.", 500


@app.route("/read")
def read_file():
    filename = request.args.get("file", "README.md")
    # Intentional: path traversal vulnerability (CodeQL should flag)
    with open(os.path.join("/data", filename)) as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
