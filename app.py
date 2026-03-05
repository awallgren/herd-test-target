try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=5)
        return output.decode()
    except FileNotFoundError:
        # The configured executable was not found on the server.
        return "Configured command executable not found on server.", 500
    except subprocess.TimeoutExpired:
        # The command took too long to complete.
        return "Command execution timed out.", 504
    except subprocess.CalledProcessError as e:
        # The command exited with a non-zero status.
        return f"Command '{cmd_key}' failed with exit code {e.returncode}.", 500
