"""Simple Flask app with intentional security issues for testing."""

from flask import Flask, request
import subprocess
import os

app = Flask(__name__)


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
    cmd = request.args.get("cmd", "echo hello")
    # Intentional: command injection vulnerability (CodeQL should flag)
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


@app.route("/read")
def read_file():
    filename = request.args.get("file", "README.md")
    base_path = "/data"
    # Resolve and validate the path (including symlinks) to prevent path traversal
    base_real = os.path.realpath(base_path)
    full_real = os.path.realpath(os.path.join(base_real, filename))
    if os.path.commonpath([base_real, full_real]) != base_real:
        # Reject paths that escape the intended base directory
        return "Invalid file path", 400
    try:
        with open(full_real) as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404
    except PermissionError:
        return "Permission denied", 403


if __name__ == "__main__":
    app.run(debug=True)
