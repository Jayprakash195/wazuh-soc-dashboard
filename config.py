import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SOC_DB_PATH", BASE_DIR / "data" / "soc.db"))
DEMO_FILE = BASE_DIR / "data" / "demo_alerts.json"
def load_env():
    f = BASE_DIR / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
