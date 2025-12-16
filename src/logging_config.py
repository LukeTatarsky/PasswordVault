import logging
import os
import sys
import traceback
import pendulum

LOG_FILE = "error.log"

def setup_logging() -> None:

    if logging.getLogger().handlers:
        return  # already configured

    logging.basicConfig(
        filename=LOG_FILE,
        filemode="a",
        level=logging.ERROR,
        format="%(message)s",
    )

    sys.excepthook = log_uncaught_exceptions


def log_uncaught_exceptions(exctype, value, tb):
    now = pendulum.now().to_iso8601_string()

    lines = []
    for frame in traceback.extract_tb(tb):
        filename = os.path.basename(frame.filename)
        lines.append(
            f'  File "{filename}", line {frame.lineno}, in {frame.name}'
        )

    trace_summary = "\n".join(reversed(lines)) if lines else "  <no traceback>"
    error_msg = f"{exctype.__name__}: {value}"

    logging.error(
        f"[{now}] Uncaught exception: {error_msg}\n"
        f"Traceback (most recent call last):\n"
        f"{trace_summary}\n"
        f"{error_msg}\n"
    )

    print("\nError! Something went wrong.", file=sys.stderr)
    print("Details saved to error.log\n", file=sys.stderr)
