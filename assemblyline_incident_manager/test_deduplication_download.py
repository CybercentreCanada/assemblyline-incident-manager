import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

UPLOADER_CWD = Path(__file__).parent 
UPLOAD_BASE = Path("/tmp/test_upload")
USER = "jdhali-cyber"
URL = "https://malware.cyber.gc.ca/"
WRITE_KEY = "/home/jdhaliwal/keys/JapjotWrite.txt"
READ_KEY = "/home/jdhaliwal/keys/JapjotRead.txt"

def setup_test_files():
    if UPLOAD_BASE.exists():
        shutil.rmtree(UPLOAD_BASE)
    (UPLOAD_BASE / "a").mkdir(parents=True, exist_ok=True)
    (UPLOAD_BASE / "b").mkdir(parents=True, exist_ok=True)

    content = b"This is a duplicate file"
    (UPLOAD_BASE / "a" / "duplicate.txt").write_bytes(content)
    # identical content → identical SHA
    shutil.copyfile(UPLOAD_BASE / "a" / "duplicate.txt", UPLOAD_BASE / "b" / "duplicate.txt")

def clean_submitter_state():
    # submitter writes these in CWD
    for fname in ("file_paths.txt", "skipped_files.txt"):
        p = UPLOADER_CWD / fname
        if p.exists():
            p.unlink()

def run_uploader(incident):
    cmd = [
        "python3", "al_incident_submitter.py",
        f"--url={URL}",
        f"--username={USER}",
        f"--apikey={WRITE_KEY}",
        "--classification=TLP:CLEAR",
        f"--path={str(UPLOAD_BASE)}",
        f"--incident_num={incident}",
        "--fresh"  
    ]
    subprocess.run(cmd, check=True, cwd=UPLOADER_CWD)

def run_downloader(incident, download_dir):
    cmd = [
        "python3", "al_incident_downloader.py",
        f"--url={URL}",
        f"--username={USER}",
        f"--apikey={READ_KEY}",
        f"--incident_num={incident}",
        "--max_score=10000",
        f"--download_path={download_dir}",      
        f"--upload_path={str(UPLOAD_BASE)}",    # must match what was used on upload
    ]
    subprocess.run(cmd, check=True, cwd=UPLOADER_CWD)

def assert_restored(download_dir):
    p1 = Path(download_dir) / "a" / "duplicate.txt"
    p2 = Path(download_dir) / "b" / "duplicate.txt"
    assert p1.exists(), f"Missing file: {p1}"
    assert p2.exists(), f"Missing file: {p2}"
    # Optional: verify content, too
    assert p1.read_bytes() == p2.read_bytes() == b"This is a duplicate file"

def test_dedup_restores_all_paths():
    incident = f"test-dup-{int(time.time())}"  # unique per run
    setup_test_files()
    clean_submitter_state()
    run_uploader(incident)

    with tempfile.TemporaryDirectory(prefix="al_download_") as dld:
        run_downloader(incident, dld)
        assert_restored(dld)
        print("Dedup test passed: both duplicate paths restored.")

if __name__ == "__main__":
    test_dedup_restores_all_paths()
