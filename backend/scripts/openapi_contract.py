import argparse
import json
from pathlib import Path

from app.core.config import Settings
from app.main import create_app

DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def render_openapi_contract() -> str:
    settings = Settings(_env_file=None)
    application = create_app(settings)
    return json.dumps(application.openapi(), indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Export the CodeRisk OpenAPI contract.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    arguments = parser.parse_args()
    rendered_contract = render_openapi_contract()

    if arguments.check:
        if not arguments.output.exists():
            raise SystemExit(f"OpenAPI contract is missing: {arguments.output}")
        if arguments.output.read_text(encoding="utf-8") != rendered_contract:
            raise SystemExit("OpenAPI contract is out of date. Regenerate it before committing.")
        return

    arguments.output.write_text(rendered_contract, encoding="utf-8")


if __name__ == "__main__":
    main()
