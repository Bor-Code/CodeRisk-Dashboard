import argparse
import signal
from threading import Event

from app.core.config import get_settings
from app.db.session import create_database, prepare_database
from app.jobs.worker import ScanWorker


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the CodeRisk scan worker.")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one queued scan and exit.",
    )
    arguments = parser.parse_args()
    settings = get_settings()
    database = create_database(settings)

    try:
        prepare_database(database, auto_create=settings.database_auto_create)
        worker = ScanWorker(database, settings)

        if arguments.once:
            worker.run_once()
            return

        stop_event = Event()

        def request_stop(_signal_number, _frame) -> None:
            stop_event.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        worker.run_forever(stop_event)
    finally:
        database.engine.dispose()


if __name__ == "__main__":
    main()
