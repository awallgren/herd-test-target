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
    # Intentional: path traversal vulnerability (CodeQL should flag)
    with open(os.path.join("/data", filename)) as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
