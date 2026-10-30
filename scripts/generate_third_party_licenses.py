#!/usr/bin/env python3
"""Generate a readable third-party license inventory for the runtime environment."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "THIRD_PARTY_LICENSES.md"
SCANNER_PACKAGES = ("pip-licenses", "prettytable", "wcwidth")
DEV_ONLY_PACKAGES = {
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "ruff",
    "mypy",
    "pip-audit",
}

# The upstream package declares MIT but its 1.9.32 wheel omits the license file.
OVERRIDES = {
    "cos-python-sdk-v5": {
        "URL": "https://github.com/tencentyun/cos-python-sdk-v5",
        "LicenseText": """MIT License

Copyright (c) 2017 腾讯云

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
""",
    },
}


def load_packages() -> list[dict]:
    command = [
        sys.executable,
        "-m",
        "piplicenses",
        "--format=json",
        "--with-urls",
        "--with-license-file",
        "--with-notice-file",
        "--ignore-packages",
        *SCANNER_PACKAGES,
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    packages = json.loads(result.stdout)

    installed_names = {package["Name"].casefold() for package in packages}
    leaked_dev_tools = installed_names & {name.casefold() for name in DEV_ONLY_PACKAGES}
    if leaked_dev_tools:
        names = ", ".join(sorted(leaked_dev_tools))
        raise SystemExit(
            f"Dev-only packages detected ({names}). Generate the production "
            "inventory in a clean environment containing only requirements.txt "
            "and pip-licenses."
        )

    for package in packages:
        package.update(OVERRIDES.get(package["Name"], {}))
        if not package.get("LicenseText") or package["LicenseText"] == "UNKNOWN":
            raise SystemExit(
                f"缺少许可证原文: {package['Name']} {package['Version']}；"
                "请从上游 LICENSE 文件补充 OVERRIDES"
            )
        if not package.get("License") or package["License"] == "UNKNOWN":
            raise SystemExit(f"许可证类型未知: {package['Name']} {package['Version']}")

    return sorted(packages, key=lambda item: item["Name"].casefold())


def render(packages: list[dict]) -> str:
    license_counts = Counter(package["License"] for package in packages)
    lines = [
        "# Third-Party Licenses",
        "",
        "This file inventories the production Python dependencies declared by",
        "`requirements.txt`, including their transitive dependencies.",
        "",
        "It is generated from a clean environment by",
        "`scripts/generate_third_party_licenses.py`. The project's own source is",
        "licensed under the root [`LICENSE`](LICENSE); the notices below apply only",
        "to their respective third-party packages.",
        "",
        "## License summary",
        "",
        "| Declared license | Packages |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {license_name} | {count} |"
        for license_name, count in sorted(license_counts.items())
    )
    lines.extend(
        [
            "",
            f"**Package count:** {len(packages)}",
            "",
            "## Packages",
            "",
        ]
    )

    for package in packages:
        name = package["Name"]
        version = package["Version"]
        url = package.get("URL")
        license_text = "\n".join(
            line.rstrip() for line in package["LicenseText"].strip().splitlines()
        )
        lines.extend(
            [
                f"### {name} {version}",
                "",
                f"**License:** `{package['License']}`",
                "",
            ]
        )
        if url and url != "UNKNOWN":
            lines.extend([f"**Source:** <{url}>", ""])
        lines.extend(
            [
                "<details>",
                "<summary>License text</summary>",
                "",
                "```text",
                license_text,
                "```",
                "",
                "</details>",
                "",
            ]
        )
        notice = package.get("NoticeText")
        if notice and notice != "UNKNOWN":
            notice_text = "\n".join(
                line.rstrip() for line in notice.strip().splitlines()
            )
            lines.extend(
                [
                    "<details>",
                    "<summary>NOTICE</summary>",
                    "",
                    "```text",
                    notice_text,
                    "```",
                    "",
                    "</details>",
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    packages = load_packages()
    OUTPUT.write_text(render(packages), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT} ({len(packages)} packages)")


if __name__ == "__main__":
    main()
