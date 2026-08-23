import json
import os
import sys
from pathlib import Path

from app.scanner import scan_repository

EXIT_INVALID_TARGET = 2
EXIT_SCAN_FAILED = 3
EXIT_RESULT_TOO_LARGE = 4


def _apply_resource_limits(*, memory_limit_mb: int, cpu_limit_seconds: int) -> None:
    if os.name == "nt":
        return

    import resource

    memory_limit_bytes = memory_limit_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit_seconds, cpu_limit_seconds))


def main() -> int:
    if len(sys.argv) != 6:
        return EXIT_SCAN_FAILED

    target, output_path, result_limit, memory_limit, cpu_limit = sys.argv[1:]

    try:
        result_limit_bytes = int(result_limit)
        memory_limit_mb = int(memory_limit)
        cpu_limit_seconds = int(cpu_limit)
        _apply_resource_limits(
            memory_limit_mb=memory_limit_mb,
            cpu_limit_seconds=cpu_limit_seconds,
        )
        report = scan_repository(target)
        payload = json.dumps(
            report.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        if len(payload) > result_limit_bytes:
            return EXIT_RESULT_TOO_LARGE

        Path(output_path).write_bytes(payload)
    except ValueError:
        return EXIT_INVALID_TARGET
    except Exception:
        return EXIT_SCAN_FAILED

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
