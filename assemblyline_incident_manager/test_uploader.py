import os
from pathlib import Path
import platform

#test would fail because linux doesn't recognize \\ as a part of a path, it just sees them as characters
#windows to linux


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
