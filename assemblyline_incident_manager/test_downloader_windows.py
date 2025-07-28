import os
from pathlib import Path
import platform
import pytest


#windows to windows normalization
@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
def test_upload_download_from_windows_path():
    original_path = r"C:\Users\Japjot\Documents\project\file.txt"

    # Upload: Normalize to Linux-style
    normalized_for_upload = Path(original_path).as_posix()  # C:/Users/Japjot/Documents/project/file.txt

  
    upload_path = "C:/Users/Japjot/Documents/project"  
    submitted_filepath = normalized_for_upload

    root_filepath = submitted_filepath.replace(upload_path, "") 
    root_filepath = root_filepath.lstrip("\\").lstrip("/")
    root_filepath = os.path.normpath(root_filepath)  

    download_path = r"D:\Downloads"
    final_path = os.path.join(download_path, root_filepath)

    expected_final = r"D:\Downloads\file.txt"
    assert final_path == expected_final

#Linux to windows normalization
@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
def test_download_from_linux_path_on_windows():
   
    submitted_filepath = "/home/japjot/docs/file.txt"
    upload_path = "/home/japjot/docs"

    # Simulate downloader logic
    root_filepath = submitted_filepath.replace(upload_path, "")  
    root_filepath = root_filepath.lstrip("\\").lstrip("/")
    root_filepath = os.path.normpath(root_filepath) 

    download_path = r"D:\Downloads"
    final_path = os.path.join(download_path, root_filepath)

    expected_final = r"D:\Downloads\file.txt"
    assert final_path == expected_final

