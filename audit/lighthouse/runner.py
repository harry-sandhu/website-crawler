import json
import subprocess
from pathlib import Path


class LighthouseRunner:

    def __init__(self):
        self.output_dir = Path("output/lighthouse")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, url: str):

        report_path = self.output_dir / "report.json"

        command = [
            "npx",
            "lighthouse",
            url,
            "--chrome-path=/usr/bin/google-chrome-stable",
            "--chrome-flags=--headless=new --no-sandbox",
            "--output=json",
            f"--output-path={report_path}",
            "--quiet",
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(result.stderr)

        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)