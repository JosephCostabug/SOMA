import json
import sys
from dataclasses import asdict

from app.earth_sync import EarthSyncConfigurationError, run_worker_once


def main() -> int:
    try:
        result = run_worker_once()
    except EarthSyncConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
