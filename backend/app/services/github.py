"""GitHub repository ingestion service.

Clones a public GitHub repository into a temporary workspace directory
so the scanner can run against it like a local path.

Security constraints
--------------------
- Only ``https://github.com`` URLs are accepted.
- The URL must end with a valid path segment (no shell metacharacters).
- The clone is performed in an isolated temp directory under the configured
  ``scan_workspace_root`` and is cleaned up by the caller.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Allow  https://github.com/<owner>/<repo>  with optional .git suffix
_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+(\.git)?$")


class InvalidGitHubURLError(ValueError):
    """Raised when the provided URL is not a supported GitHub HTTPS URL."""


class GitCloneError(RuntimeError):
    """Raised when ``git clone`` fails."""


def validate_github_url(url: str) -> str:
    """Return the normalised URL or raise :class:`InvalidGitHubURLError`."""
    url = url.strip().rstrip("/")
    if not _GITHUB_URL_RE.match(url):
        raise InvalidGitHubURLError(
            "Only public https://github.com/<owner>/<repo> URLs are supported."
        )
    return url


def clone_repository(url: str, workspace_root: Path | None = None) -> Path:
    """Clone *url* into a fresh temp directory and return the clone path.

    The caller is responsible for deleting the directory when it is no longer
    needed (e.g. after the scan completes).

    Parameters
    ----------
    url:
        A validated ``https://github.com`` URL.
    workspace_root:
        Parent directory for the temp clone.  Defaults to the system temp dir.
    """
    validated_url = validate_github_url(url)

    parent = workspace_root or Path(tempfile.gettempdir())
    parent.mkdir(parents=True, exist_ok=True)
    clone_dir = Path(tempfile.mkdtemp(prefix="coderisk-clone-", dir=parent))

    logger.info("Cloning %s into %s", validated_url, clone_dir)

    try:
        result = subprocess.run(  # noqa: S603
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                validated_url,
                str(clone_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise GitCloneError(f"git clone timed out for {validated_url}") from exc
    except OSError as exc:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise GitCloneError(f"git not found or clone failed: {exc}") from exc

    if result.returncode != 0:
        shutil.rmtree(clone_dir, ignore_errors=True)
        raise GitCloneError(f"git clone exited {result.returncode}: {result.stderr[:200]}")

    return clone_dir
