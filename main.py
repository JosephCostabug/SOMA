import os
from pathlib import Path
import sys
import tempfile


_BACKEND_DIRECTORY = Path(__file__).resolve().parent / "backend"
sys.path.insert(0, str(_BACKEND_DIRECTORY))

if os.environ.get("VERCEL") == "1":
    os.environ.setdefault(
        "HEALTH_DB_PATH",
        str(Path(tempfile.gettempdir()) / "soma-health-monitoring.sqlite3"),
    )

from app.main import app
