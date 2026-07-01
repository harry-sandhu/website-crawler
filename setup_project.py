from pathlib import Path

folders = [
    "audit",
    "browser",
    "reports",
    "reports/templates",
    "output",
    "output/screenshots",
    "output/json",
    "output/pdf",
    "output/html",
    "rules",
    "utils",
    "logs",
    "tests",
]

files = [
    "main.py",
    "config.py",
    "requirements.txt",
    ".gitignore",
    "README.md",

    "audit/__init__.py",
    "audit/seo.py",
    "audit/performance.py",
    "audit/accessibility.py",
    "audit/security.py",
    "audit/mobile.py",
    "audit/network.py",
    "audit/console.py",
    "audit/forms.py",
    "audit/contact.py",
    "audit/images.py",
    "audit/links.py",
    "audit/visual.py",

    "browser/__init__.py",
    "browser/browser.py",
    "browser/screenshots.py",

    "reports/__init__.py",
    "reports/pdf_report.py",
    "reports/html_report.py",
    "reports/json_report.py",

    "utils/__init__.py",
    "utils/logger.py",
    "utils/helpers.py",

    "tests/__init__.py",
]

gitignore = """# Python
__pycache__/
*.pyc

# Virtual Environment
.venv/

# Output
output/

# Logs
logs/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
"""

readme = """# Website Auditor

Automated website auditing tool built with Python.

Features:
- SEO Audit
- Accessibility Audit
- Performance Audit
- Security Audit
- Console Error Detection
- Mobile Testing
- PDF Reports
"""

requirements = ""

for folder in folders:
    Path(folder).mkdir(parents=True, exist_ok=True)

for file in files:
    path = Path(file)

    if not path.exists():
        path.touch()

Path(".gitignore").write_text(gitignore)
Path("README.md").write_text(readme)
Path("requirements.txt").write_text(requirements)

print("✅ Project structure created successfully!")