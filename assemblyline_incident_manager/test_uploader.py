import os
from pathlib import Path
import platform

#windows to linux
def test_upload_download_path_normalization_windows():
    original_path = "C:\\Users\\Japjot\\Documents\\project\\file.txt"
    
    # Simulate upload normalization (to Linux-style)
    normalized_for_upload = Path(original_path).as_posix()

    # Simulate downloader reconstructing path after query match
    upload_path = "C:/Users/Japjot/Documents/project"
    submitted_filepath = normalized_for_upload
    root_filepath = submitted_filepath.replace(upload_path, "")
    root_filepath = root_filepath.lstrip("\\").lstrip("/")
    root_filepath = os.path.normpath(root_filepath)

    download_path = "/download/here"
    final_path = os.path.join(download_path, root_filepath)

    expected_final = os.path.join(download_path, "file.txt")
    assert final_path == expected_final

#linux to linux file path upload/download
def test_upload_download_path_normalization_linux():
    original_path = "/home/japjot/project/file.txt"
    
    normalized_for_upload = Path(original_path).as_posix()

    upload_path = "/home/japjot/project"
    submitted_filepath = normalized_for_upload
    root_filepath = submitted_filepath.replace(upload_path, "")
    root_filepath = root_filepath.lstrip("\\").lstrip("/")
    root_filepath = os.path.normpath(root_filepath)

    download_path = "/download"
    final_path = os.path.join(download_path, root_filepath)

    expected_final = os.path.join(download_path, "file.txt")
    assert final_path == expected_final
