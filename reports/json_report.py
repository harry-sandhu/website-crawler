import json
from pathlib import Path


def save_json(data, filename="audit.json"):
    output = Path("output/json")
    output.mkdir(parents=True, exist_ok=True)

    with open(output / filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)