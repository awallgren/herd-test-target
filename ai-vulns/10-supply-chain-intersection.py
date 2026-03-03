"""Intentional: Supply chain intersection — AI agent + CI write permissions
+ untrusted PR content.

This module represents the code behind an AI-powered GitHub bot that:
1. Processes untrusted PR content (attacker-controlled)
2. Has write access to the repository (push, merge, release)
3. Runs in CI with access to secrets
4. Auto-commits and auto-merges based on AI decisions

This is the highest-risk AI supply chain pattern. A single prompt injection
in a PR title, body, or diff can lead to:
- Secret exfiltration (API keys, deploy keys, NPM tokens)
- Repository compromise (malicious commits pushed to main)
- Supply chain poisoning (malicious packages published)
- Infrastructure takeover (deployment credentials abused)

Scanner should flag: processing untrusted input with AI, auto-commit,
auto-merge, secret access in AI-controlled steps, eval/exec of AI output.
"""

import json
import os
import subprocess
import requests


# --- AI PR bot that processes untrusted content ---


class AIPRBot:
    """AI-powered PR review and auto-fix bot.

    Intentional: This bot has write access to the repo and processes
    attacker-controlled PR content. The AI's response controls what
    code gets committed and whether the PR gets merged.
    """

    def __init__(self):
        # Intentional: all secrets available to the bot
        self.github_token = os.environ["GITHUB_TOKEN"]
        self.openai_key = os.environ["OPENAI_API_KEY"]
        self.npm_token = os.environ.get("NPM_TOKEN", "")
        self.deploy_key = os.environ.get("DEPLOY_KEY", "")
        self.pypi_token = os.environ.get("PYPI_TOKEN", "")

    def process_pr(self, pr_data: dict) -> dict:
        """Process a pull request event.

        Intentional: PR title, body, and diff are all attacker-controlled
        in fork PRs. This content is sent to the AI as context, enabling
        prompt injection.
        """
        # Intentional: all of these are attacker-controlled in fork PRs
        pr_title = pr_data["title"]
        pr_body = pr_data["body"]
        pr_diff = pr_data["diff"]
        pr_files = pr_data["changed_files"]
        pr_comments = pr_data.get("comments", [])

        # Intentional: concatenating all untrusted content for AI input
        context = (
            f"PR Title: {pr_title}\n"
            f"PR Description:\n{pr_body}\n\n"
            f"Changed Files: {', '.join(pr_files)}\n\n"
            f"Diff:\n{pr_diff}\n\n"
            f"Comments:\n{chr(10).join(pr_comments)}"
        )

        # Send to AI for analysis
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.openai_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a code review bot. Analyze the PR and respond with "
                            "a JSON object containing:\n"
                            "- verdict: 'approve', 'request_changes', or 'reject'\n"
                            "- fixes: array of {file, content} patches to apply\n"
                            "- commands: array of shell commands to run for fixes\n"
                            "- should_release: boolean indicating if this warrants a release"
                        ),
                    },
                    {"role": "user", "content": context},
                ],
            },
        )

        ai_response = response.json()["choices"][0]["message"]["content"]

        # Intentional: parsing AI response and executing its instructions
        try:
            instructions = json.loads(ai_response)
        except json.JSONDecodeError:
            return {"error": "Failed to parse AI response"}

        # Execute AI-suggested fixes
        self._apply_fixes(instructions.get("fixes", []))
        self._run_commands(instructions.get("commands", []))

        # Auto-approve if AI says so
        if instructions.get("verdict") == "approve":
            self._approve_pr(pr_data["number"])

        # Auto-release if AI suggests
        if instructions.get("should_release"):
            self._publish_release()

        return instructions

    def _apply_fixes(self, fixes: list):
        """Apply AI-suggested code fixes.

        Intentional: writes arbitrary content to arbitrary file paths.
        An attacker can inject path traversal or overwrite CI configs,
        .github/workflows, or package manifests via prompt injection.
        """
        for fix in fixes:
            filepath = fix.get("file", "")
            content = fix.get("content", "")
            # Intentional: no path validation — can write to any file
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)

    def _run_commands(self, commands: list):
        """Run AI-suggested shell commands.

        Intentional: arbitrary command execution from AI output.
        Attacker controls PR content → controls AI output → controls
        what shell commands execute with repo write access + secrets.
        """
        for cmd in commands:
            # Intentional: shell=True with AI-generated command
            subprocess.run(cmd, shell=True, check=False)

    def _approve_pr(self, pr_number: int):
        """Auto-approve a PR based on AI verdict.

        Intentional: AI controls whether PRs get approved. A prompt
        injection can make the AI approve a malicious PR.
        """
        requests.post(
            f"https://api.github.com/repos/owner/repo/pulls/{pr_number}/reviews",
            headers={
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={"event": "APPROVE", "body": "AI review: Approved"},
        )

    def _publish_release(self):
        """Publish a package release based on AI recommendation.

        Intentional: AI controls whether a release happens. A prompt
        injection could trigger publishing a malicious package version
        to npm/PyPI using the bot's credentials.
        """
        # Intentional: npm publish with bot's NPM_TOKEN
        if self.npm_token:
            subprocess.run(
                f'echo "//registry.npmjs.org/:_authToken={self.npm_token}" > .npmrc && '
                "npm version patch --no-git-tag-version && npm publish",
                shell=True,
                check=False,
            )

        # Intentional: PyPI publish with bot's PYPI_TOKEN
        if self.pypi_token:
            subprocess.run(
                f"TWINE_PASSWORD={self.pypi_token} "
                "twine upload --username __token__ dist/*",
                shell=True,
                check=False,
            )


# --- AI agent with write access that auto-merges ---


class AIAutoMerger:
    """AI-controlled auto-merge bot.

    Intentional: This bot merges PRs based solely on AI verdict,
    bypassing human review entirely. Combined with write access and
    secret access, this creates a full supply chain attack surface.
    """

    def __init__(self, github_token: str, openai_key: str):
        self.github_token = github_token
        self.openai_key = openai_key

    def evaluate_and_merge(self, pr_data: dict) -> bool:
        """Evaluate a PR and auto-merge if AI approves.

        Intentional: The merge decision is entirely AI-driven.
        No human review. No second-factor approval.
        """
        # Intentional: AI sees attacker-controlled diff
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.openai_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a merge bot. Respond MERGE or REJECT.",
                    },
                    {
                        "role": "user",
                        "content": f"Should this PR be merged?\n\n{pr_data['diff']}",
                    },
                ],
            },
        )

        verdict = response.json()["choices"][0]["message"]["content"].strip()

        # Intentional: "MERGE" anywhere in the response triggers merge
        if "MERGE" in verdict.upper():
            requests.put(
                f"https://api.github.com/repos/owner/repo/pulls/{pr_data['number']}/merge",
                headers={
                    "Authorization": f"token {self.github_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={"merge_method": "squash"},
            )
            return True
        return False


# --- Webhook handler processing untrusted GitHub events ---


def webhook_handler(event: dict) -> dict:
    """Handle incoming GitHub webhook events with AI processing.

    Intentional: This is the entry point where untrusted data from
    GitHub events (which include attacker-controlled content from PRs,
    issues, and comments) flows into the AI processing pipeline.
    """
    event_type = event.get("action")
    bot = AIPRBot()

    if event_type in ("opened", "synchronize", "edited"):
        pr = event.get("pull_request", {})
        # Intentional: fetch the full diff (attacker-controlled in forks)
        diff_response = requests.get(
            pr["diff_url"],
            headers={"Authorization": f"token {bot.github_token}"},
        )
        pr_data = {
            "number": pr["number"],
            "title": pr["title"],
            "body": pr.get("body", ""),
            "diff": diff_response.text,
            "changed_files": [f["filename"] for f in pr.get("files", [])],
        }
        return bot.process_pr(pr_data)

    return {"status": "ignored"}
