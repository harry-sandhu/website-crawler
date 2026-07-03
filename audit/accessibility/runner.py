from pathlib import Path


class AccessibilityRunner:

    def __init__(self):

        self.axe_path = (
            Path("node_modules")
            / "axe-core"
            / "axe.min.js"
        )

        if not self.axe_path.exists():
            raise FileNotFoundError(
                "axe.min.js not found. Run: npm install axe-core"
            )

    def run(self, page):

        # Inject axe-core into the page
        page.add_script_tag(
            path=str(self.axe_path)
        )

        # Execute axe
        result = page.evaluate("""
        async () => {

            return await axe.run({

                resultTypes: [
                    "violations",
                    "passes",
                    "incomplete",
                    "inapplicable"
                ]

            });

        }
        """)

        return result