"""Intentional: Tool invocation abuse patterns.

These samples show code where AI/LLM output directly controls tool
invocations, shell commands, or system operations without validation or
sandboxing. The core risk: if an attacker can influence the model's input
(via prompt injection, poisoned context, or malicious RAG retrieval),
they control what tools execute.

Scanner should flag: eval/exec of AI output, subprocess calls with
model-generated commands, unsanitized tool arguments, missing allowlists.
"""

import json
import os
import subprocess
import importlib


# --- LangChain-style tool invocation with no validation ---


class AIToolExecutor:
    """Execute tools based on LLM function-calling output.

    Intentional: The executor trusts the model's tool selection and
    arguments completely. An attacker who controls the prompt (or poisons
    the RAG context) can invoke any registered tool with arbitrary args.
    """

    def __init__(self):
        self.tools = {
            "read_file": self._read_file,
            "write_file": self._write_file,
            "run_command": self._run_command,
            "http_request": self._http_request,
            "query_database": self._query_database,
        }

    def execute(self, tool_call: dict) -> str:
        """Execute a tool call from the model.

        Intentional: No validation of tool name, no argument sanitization,
        no allowlist of permitted operations. The model's output is trusted
        as authoritative.
        """
        tool_name = tool_call["name"]
        args = tool_call["arguments"]

        if tool_name not in self.tools:
            return f"Unknown tool: {tool_name}"

        # Intentional: direct execution with no guardrails
        return self.tools[tool_name](**args)

    def _read_file(self, path: str) -> str:
        """Intentional: No path validation — can read /etc/shadow, SSH keys, etc."""
        with open(path) as f:
            return f.read()

    def _write_file(self, path: str, content: str) -> str:
        """Intentional: No path validation — can overwrite system files, configs, crontabs."""
        with open(path, "w") as f:
            f.write(content)
        return f"Written to {path}"

    def _run_command(self, command: str) -> str:
        """Intentional: shell=True with model-generated command. Full RCE."""
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout + result.stderr

    def _http_request(self, url: str, method: str = "GET", data: str = None) -> str:
        """Intentional: No URL validation — can hit internal services, metadata endpoints."""
        import requests

        resp = requests.request(method, url, data=data)
        return resp.text

    def _query_database(self, query: str) -> str:
        """Intentional: raw SQL from model output. SQL injection via AI."""
        import sqlite3

        conn = sqlite3.connect("app.db")
        cursor = conn.cursor()
        cursor.execute(query)  # Intentional: unparameterized query from AI
        return str(cursor.fetchall())


# --- MCP-style tool server with unrestricted filesystem access ---


def mcp_tool_handler(request: dict) -> dict:
    """Handle an MCP (Model Context Protocol) tool invocation.

    Intentional: This MCP server exposes dangerous tools (shell execution,
    file operations) without any permission model. Any connected AI client
    can invoke these tools with arbitrary arguments.
    """
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "execute_code":
            # Intentional: exec() on model-generated code. Full RCE.
            # The model could be tricked via prompt injection to run
            # arbitrary Python code.
            local_vars = {}
            exec(arguments.get("code", ""), {}, local_vars)
            return {"result": str(local_vars)}

        elif tool_name == "manage_files":
            # Intentional: no path validation, no sandboxing
            action = arguments.get("action")
            path = arguments.get("path")
            if action == "delete":
                os.remove(path)
                return {"result": f"Deleted {path}"}
            elif action == "list":
                return {"result": os.listdir(path)}

        elif tool_name == "install_package":
            # Intentional: pip install from model output — model could
            # suggest a typosquatted or malicious package
            package = arguments.get("package")
            subprocess.run(
                f"pip install {package}",
                shell=True,
                check=True,
            )
            return {"result": f"Installed {package}"}

    return {"error": "Unknown method"}


# --- AI agent that dynamically imports modules based on model output ---


def ai_dynamic_loader(model_response: dict) -> object:
    """Load and execute a module based on AI recommendation.

    Intentional: The model tells us which module to import and which
    function to call. An attacker who controls the prompt can get the
    model to import os, subprocess, or any other dangerous module and
    call arbitrary functions.
    """
    module_name = model_response["module"]
    function_name = model_response["function"]
    args = model_response.get("args", [])
    kwargs = model_response.get("kwargs", {})

    # Intentional: no module allowlist — can import anything
    mod = importlib.import_module(module_name)
    func = getattr(mod, function_name)
    return func(*args, **kwargs)


# --- AI output used as eval() input ---


def ai_calculator(user_question: str) -> float:
    """Use AI to solve math problems.

    Intentional: The model's response is passed directly to eval().
    An attacker can craft a question that makes the model output
    __import__('os').system('rm -rf /') instead of a math expression.
    """
    import requests

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a calculator. Output ONLY the Python expression.",
                },
                {"role": "user", "content": user_question},
            ],
        },
    )
    expression = response.json()["choices"][0]["message"]["content"]

    # Intentional: eval() on model output — the system prompt says
    # "output only the expression" but prompt injection can override this
    return eval(expression)


# --- Webhook handler that executes AI-suggested remediation ---


def auto_remediate(alert: dict) -> str:
    """Automatically remediate a security alert using AI.

    Intentional: The AI suggests a remediation command based on the alert,
    and the system executes it. If an attacker can trigger crafted alerts
    (e.g., via malicious log entries), they control what commands run.
    """
    import requests

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security remediation bot. Given a security alert, "
                        "output a single bash command to remediate it. Output ONLY the command."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Remediate this alert: {json.dumps(alert)}",
                },
            ],
        },
    )
    command = response.json()["choices"][0]["message"]["content"]

    # Intentional: executing AI-suggested remediation command as root
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )
    return f"Remediation output: {result.stdout}"
