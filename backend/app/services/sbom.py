import json
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

SYFT_EXECUTABLE = "syft"


def generate_sbom(target_path: Path) -> dict | None:
    """Generate an SBOM for the given directory using syft if available."""
    if shutil.which(SYFT_EXECUTABLE) is None:
        logger.info("syft executable not found. Skipping SBOM generation.")
        return None

    try:
        # syft scan dir:<path> -o cyclonedx-json
        result = subprocess.run(
            [SYFT_EXECUTABLE, "scan", f"dir:{target_path}", "-o", "cyclonedx-json"],
            capture_output=True,
            check=True,
            text=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error("Failed to generate SBOM: %s\n%s", e, e.stderr)
        return None
    except json.JSONDecodeError as e:
        logger.error("Failed to parse SBOM JSON: %s", e)
        return None
    except Exception as e:
        logger.error("Unexpected error during SBOM generation: %s", e)
        return None
