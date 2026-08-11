from pathlib import Path

URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"
API_KEY = '9bcb8b9b5a170e001487313be78860680878de41'
SCORE_THRESHOLD = 50
PARSE_DEBUG = True
DB_DEBUG = False
ANALYSIS_DEBUG = False

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"
RESOURCES_DIR = PROJECT_ROOT / "resources"
PCAPS_DIR = PROJECT_ROOT / "pcaps"
DATABASE_PATH = PROJECT_ROOT / "OSFP_db.db"
GROUND_TRUTH_PATH = RESOURCES_DIR / "ground_truth.json"
DEFAULT_PCAP_PATH = PCAPS_DIR / "merged_output.pcapng"
MODEL_ARTIFACT_NAME = "os_classifier_pair.joblib"
MODEL_DIR = PROJECT_ROOT / "models"
LEGACY_MODEL_DIR = PROJECT_ROOT / "model"


def resolve_model_artifact_path() -> Path:
	candidates = (
		LEGACY_MODEL_DIR / MODEL_ARTIFACT_NAME,
		MODEL_DIR / MODEL_ARTIFACT_NAME,
	)
	return next((path for path in candidates if path.exists()), candidates[0])


# Dashboard & live capture settings
LOW_CONFIDENCE_THRESHOLD = 0.6   # devices with any confidence_* below this are flagged
LIVE_IFACE = "WiFi"              # default interface for live_capture.py (override with --iface)
DASHBOARD_PORT = 5000            # Flask dashboard port (binds to 127.0.0.1)