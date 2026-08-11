import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from scripts.parsepcap import parse_pcap
from database.db_utils import create_tables
from config import LOGS_DIR, RESOURCES_DIR



def ensure_dirs() -> int | None:
    LOGS_DIR.mkdir(exist_ok=True)
    if not RESOURCES_DIR.is_dir():
        print('\nError : Resource dir does not exist.')
        return -1
    p0f_path = RESOURCES_DIR / 'p0f.fp'
    if not p0f_path.is_file():
        print("\np0f.fp not found! fetch from https://github.com/p0f/p0f/blob/master/p0f.fp and place it in resources/.")
        return -1
    return 0


def main():
    if ensure_dirs() == -1:
        print('Parsing stopped due to directory errors')
        return
        
    create_tables()
    parse_pcap()


if __name__ == "__main__":
    main()
