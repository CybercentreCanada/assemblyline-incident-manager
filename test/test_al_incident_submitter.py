import pytest

API_KEY_FILE = "./apikey.txt"
TEST_DIR = "./delete_me_dir"


@pytest.fixture
def log():
    import logging
    log = logging.getLogger(__name__)
    return log


@pytest.fixture
def dummy_al_client_class_instance():
    class DummyALClient:
        @staticmethod
        def ingest(*args, **kwargs):
            return {"ingest_id": "blah"}
    return DummyALClient()


class TestFileSubmitter:
    @classmethod
    def setup_class(cls):
        from os import path, mkdir, urandom
        if not path.exists(TEST_DIR):
            mkdir(TEST_DIR)
            for i in range(1000):
                file_contents = urandom(100)
                with open(f"{TEST_DIR}/delete_me_file_{i}.txt", "wb") as f:
                    f.write(file_contents)

    @classmethod
    def teardown_class(cls):
        from os import path, remove, rmdir, listdir
        if not path.exists(TEST_DIR):
            return
        files = listdir(TEST_DIR)
        for file in files:
            remove(path.join(TEST_DIR, file))
        rmdir(TEST_DIR)

    @staticmethod
    @pytest.mark.parametrize("data, expected_result", [
        (b"blah", '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52')
    ])
    def test_get_id_from_data(data, expected_result):
        from os import remove
        from assemblyline_incident_manager.al_incident_submitter import get_id_from_data
        SOME_FILE = "some_file.txt"
        with open(SOME_FILE, "wb") as f:
            f.write(b"blah")
        assert get_id_from_data(SOME_FILE) == expected_result
        remove(SOME_FILE)

    @staticmethod
    @pytest.mark.parametrize("case, command_line_options", [
        (
                "invalid_url", [
                    "--url", "blah",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah"
                ]
        ),
        (
                "testing", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                    "--is_test"
                ]
        ),
        (
                "testing", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                    "-t"
                ]
        ),
        (
                "fresh", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                    "--fresh"
                ]
        ),
        (
                "fresh", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                    "-f"
                ]
        ),
        (
                "ingesting", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "resume_from_file_path", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "invalid_size_small", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "invalid_size_big", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "duplicate_file", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "resume_from_file_path_with_skipped_file", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                ]
        ),
        (
                "no_threads", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--ttl", 1,
                    "--classification", "blah",
                    "--service_selection", "blah,blah",
                    "--path", TEST_DIR,
                    "--incident_num", "blah",
                    "--threads", 0,
                ]
        ),
    ])
    def test_main(case, command_line_options, mocker):
        from assemblyline_incident_manager.al_incident_submitter import main, FILE_PATHS, SKIPPED_FILE_PATHS
        from os import urandom, remove, path
        from click.testing import CliRunner

        with open(API_KEY_FILE, "w") as f:
            f.write("blah")

        mocker.patch("helper.get_client", return_value="blah")
        mocker.patch("assemblyline_incident_manager.al_incident_submitter._test_ingest_file")
        mocker.patch("assemblyline_incident_manager.al_incident_submitter._ingest_file")

        if case == "resume_from_file_path":
            from assemblyline_incident_manager.al_incident_submitter import FILE_PATHS
            with open(FILE_PATHS, "wb") as f:
                f.write((f"{TEST_DIR}/delete_me_file_500.txt\n").encode())
        elif case == "resume_from_file_path_with_skipped_file":
            from assemblyline_incident_manager.al_incident_submitter import FILE_PATHS, SKIPPED_FILE_PATHS
            with open(FILE_PATHS, "wb") as f:
                f.write((f"{TEST_DIR}/delete_me_file_500.txt\n").encode())
            with open(SKIPPED_FILE_PATHS, "wb") as f:
                f.write((f"{TEST_DIR}/delete_me_file_500.txt\n").encode())
        elif case == "invalid_size_small":
            from assemblyline_incident_manager.al_incident_submitter import MIN_FILE_SIZE
            file_contents = urandom(MIN_FILE_SIZE-1)
            with open(f"{TEST_DIR}/file_small.txt", "wb") as f:
                f.write(file_contents)
        elif case == "invalid_size_big":
            from assemblyline_incident_manager.al_incident_submitter import MAX_FILE_SIZE
            file_contents = urandom(MAX_FILE_SIZE+1)
            with open(f"{TEST_DIR}/file_big.txt", "wb") as f:
                f.write(file_contents)
        elif case == "duplicate_file":
            from shutil import copyfile
            copyfile(f"{TEST_DIR}/delete_me_file_500.txt", f"{TEST_DIR}/file_copy.txt")

        # Then setup the test
        runner = CliRunner()
        result = runner.invoke(main, command_line_options)
        assert result.exit_code == 0

        if case == "invalid_size_small":
            remove(f"{TEST_DIR}/file_small.txt")
        elif case == "invalid_size_big":
            remove(f"{TEST_DIR}/file_big.txt")
        elif case == "duplicate_file":
            remove(f"{TEST_DIR}/file_copy.txt")
        if path.exists(FILE_PATHS):
            remove(FILE_PATHS)
        remove(API_KEY_FILE)
        if path.exists(SKIPPED_FILE_PATHS):
            remove(SKIPPED_FILE_PATHS)

    @staticmethod
    @pytest.mark.parametrize("values, expected_result", [
        ((1, "TLP:W", ["blah1", "blah2"], True, 100), {"ttl": 1, "classification": "TLP:W", "services": {"selected": ["blah1", "blah2"], "resubmit": ["Dynamic Analysis"]}, "priority": 100}),
        ((1, "TLP:W", ["blah1"], False, 1000), {"ttl": 1, "classification": "TLP:W", "services": {"selected": ["blah1"], "resubmit": []}, "priority": 1000}),
    ])
    def test_generate_settings(values, expected_result):
        from assemblyline_incident_manager.al_incident_submitter import _generate_settings
        assert _generate_settings(*values) == expected_result

    @staticmethod
    def test_freshen_up(mocker):
        from os import urandom, path
        from assemblyline_incident_manager.al_incident_submitter import _freshen_up, FILE_PATHS, SKIPPED_FILE_PATHS, LOG_FILE
        file_contents = urandom(100)
        # Linux
        with open(FILE_PATHS, "wb") as f:
            f.write(file_contents)
        with open(SKIPPED_FILE_PATHS, "wb") as f:
            f.write(file_contents)
        with open(LOG_FILE, "wb") as f:
            f.write(file_contents)
        _freshen_up()
        assert not path.exists(FILE_PATHS)
        assert not path.exists(SKIPPED_FILE_PATHS)
        assert path.exists(LOG_FILE)

        # Windows
        mocker.patch("os.remove", side_effect=PermissionError)
        with open(FILE_PATHS, "wb") as f:
            f.write(file_contents)
        with open(SKIPPED_FILE_PATHS, "wb") as f:
            f.write(file_contents)
        with open(LOG_FILE, "wb") as f:
            f.write(file_contents)
        _freshen_up()
        assert path.exists(FILE_PATHS) and not path.getsize(FILE_PATHS)
        assert path.exists(SKIPPED_FILE_PATHS) and not path.getsize(SKIPPED_FILE_PATHS)
        assert path.exists(LOG_FILE)

    @staticmethod
    def test_file_has_valid_size(mocker):
        from assemblyline_incident_manager.al_incident_submitter import _file_has_valid_size, MIN_FILE_SIZE, MAX_FILE_SIZE

        too_small_file_path = "/too/small"
        mocker.patch("os.path.getsize", return_value=MIN_FILE_SIZE-1)
        assert _file_has_valid_size(too_small_file_path, too_small_file_path) == (False, 0, 1)

        too_big_file_path = "/too/big"
        mocker.patch("os.path.getsize", return_value=MAX_FILE_SIZE+1)
        assert _file_has_valid_size(too_big_file_path, too_big_file_path) == (False, 1, 0)

        just_right_file_path = "/just/right"
        mocker.patch("os.path.getsize", return_value=(MAX_FILE_SIZE+MIN_FILE_SIZE)/2)
        assert _file_has_valid_size(just_right_file_path, just_right_file_path) == (True, 0, 0)

    @staticmethod
    def test_test_ingest_file(dummy_al_client_class_instance):
        from assemblyline_incident_manager.al_incident_submitter import _test_ingest_file
        _test_ingest_file(dummy_al_client_class_instance, {}, "blah", True)
        assert True

    @staticmethod
    def test_ingest_file(dummy_al_client_class_instance):
        from assemblyline_incident_manager.al_incident_submitter import _ingest_file
        _ingest_file("blah", "blah", "blah", dummy_al_client_class_instance, {}, "blah", True)
        assert True

    @staticmethod
    def test_get_most_recent_file_path(mocker):
        from os import remove, path
        from assemblyline_incident_manager.al_incident_submitter import _get_most_recent_file_path, FILE_PATHS
        mocker.patch("al_incident_submitter.hash_table", return_value=[])
        if path.exists(FILE_PATHS):
            remove(FILE_PATHS)
        assert _get_most_recent_file_path() == (False, None)

        file_sha_1 = "blahblahblah1"
        file_sha_2 = "blahblahblah2"
        with open(file_sha_2, "wb") as f:
            f.write(b"yabadaba")
        mocker.patch("al_incident_submitter.hash_table", return_value=[])
        with open(FILE_PATHS, "wb") as f:
            f.write(file_sha_1.encode() + b"\n" + file_sha_2.encode() + b"\n")

        assert _get_most_recent_file_path() == (True, file_sha_2)

        file_sha_3 = "hithere"
        with open(file_sha_3, "wb") as f:
            f.write(b"yabadaba")
        mocker.patch("al_incident_submitter.hash_table", return_value=[])
        with open(FILE_PATHS, "wb") as f:
            f.write(file_sha_3.encode() + b"\n")

        assert _get_most_recent_file_path() == (True, file_sha_3)
        remove(FILE_PATHS)
        remove(file_sha_2)
        remove(file_sha_3)
