import os
import subprocess
import shutil

def setup_test_files(base_dir="/tmp/test_upload"):
    os.makedirs(f"{base_dir}/a", exist_ok=True)
    os.makedirs(f"{base_dir}/b", exist_ok=True)
    with open(f"{base_dir}/a/duplicate.txt", "w") as f:
        f.write("This is a duplicate file")
    shutil.copy(f"{base_dir}/a/duplicate.txt", f"{base_dir}/b/duplicate.txt")

def submit_files():
    cmd = [
        "python3", "al_incident_submitter.py",
        "--url=https://malware.cyber.gc.ca/",
        "--username=jdhali-cyber",
        "--apikey=/home/jdhaliwal/keys/JapjotWrite.txt",
        "--classification=TLP:CLEAR",
        "--path=/tmp/test_upload",
        "--incident_num=test-dup"
    ]
    subprocess.run(cmd, check=True)

def download_files():
    if os.path.exists("/tmp/test_download"):
        shutil.rmtree("/tmp/test_download")
    os.makedirs("/tmp/test_download")

    cmd = [
        "python3", "al_incident_downloader.py",
        "--url=https://malware.cyber.gc.ca/",
        "--username=jdhali-cyber",
        "--apikey=/home/jdhaliwal/keys/JapjotRead.txt",
        "--incident_num=test-dup",
        "--max_score=10000",
        "--download_path=/tmp/test_download",
        "--upload_path=/tmp/test_upload"
    ]
    subprocess.run(cmd, check=True)


def assert_both_files_restored():
    path1 = "/tmp/test_download/a/duplicate.txt"
    path2 = "/tmp/test_download/b/duplicate.txt"
    assert os.path.exists(path1), f"Missing file: {path1}"
    assert os.path.exists(path2), f"Missing file: {path2}"


def test_deduplication_restores_all_duplicates():
    print("Setting up test files...")
    setup_test_files()
    submit_files()
    download_files()
    assert_both_files_restored()
    print("Deduplication test passed (both files restored correctly)")


if __name__ == "__main__":
    test_deduplication_restores_all_duplicates()
