import pytest

API_KEY_FILE = "./apikey.txt"


@pytest.fixture
def dummy_al_client_instance():
    class DummyStream:
        @staticmethod
        def submission(*args, **kwargs):
            return [{
                "sid": "blah"
            }]

    class DummySearch:
        def __init__(self):
            self.stream = DummyStream()

    class DummySubmission:
        def __call__(self, *args, **kwargs):
            return {
                "files": [{"sha256": "blah"}],
                "metadata": {
                    "filename": "blah"
                },
                "max_score": 0,
                "errors": {}
            }

        @staticmethod
        def is_completed(sid: str) -> bool:
            return True

    class DummyALClient:
        def __init__(self):
            self.search = DummySearch()
            self.submission = DummySubmission()

    yield DummyALClient()


class TestResultAnalyzer:
    @staticmethod
    @pytest.mark.parametrize("case, command_line_options", [
        (
                "invalid_url", [
                    "--url", "blah",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--incident_num", "blah"
                ]
        ),
        (
                "testing", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--incident_num", "blah",
                    "--is_test",
                ]
        ),
        (
                "testing", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--incident_num", "blah",
                    "-t",
                ]
        ),
        (
                "report_exists", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--incident_num", "blah",
                ]
        ),
        (
                "write_report", [
                    "--url", "http://real_domain.com",
                    "--username", "blah",
                    "--apikey", API_KEY_FILE,
                    "--incident_num", "blah",
                ]
        ),
    ])
    def test_main(case, command_line_options, dummy_al_client_instance, mocker):
        from click.testing import CliRunner
        from os import urandom, remove
        from assemblyline_incident_manager.al_incident_analyzer import main, REPORT_FILE
        mocker.patch("assemblyline_incident_manager.al_incident_analyzer.get_client", return_value=dummy_al_client_instance)

        with open(API_KEY_FILE, "w") as f:
            f.write("blah")

        if case == "report_exists":
            file_contents = urandom(100)
            with open(REPORT_FILE, "wb") as f:
                f.write(file_contents)
            mocker.patch("builtins.input", return_value="n")

        # Then setup the test
        runner = CliRunner()
        result = runner.invoke(main, command_line_options)
        assert result.exit_code == 0

        if case == "report_exists":
            remove(REPORT_FILE)
        elif case == "write_report":
            remove(REPORT_FILE)
        remove(API_KEY_FILE)


    @staticmethod
    def test_handle_overwrite(mocker):
        from os import urandom
        from assemblyline_incident_manager.al_incident_analyzer import _handle_overwrite, REPORT_FILE

        mocker.patch("builtins.input", return_value="n")
        assert _handle_overwrite() is False

        mocker.patch("builtins.input", return_value="x")
        assert _handle_overwrite() is False

        mocker.patch("builtins.input", return_value="y")
        file_contents = urandom(100)
        with open(REPORT_FILE, "wb") as f:
            f.write(file_contents)
        assert _handle_overwrite() is True

    @staticmethod
    @pytest.mark.parametrize("file_name, expected_result", [
        ("blah", "blah"),
        ("blah,blah.blah", "blahblah.blah"),
    ])
    def test_prepare_file_name(file_name, expected_result):
        from assemblyline_incident_manager.al_incident_analyzer import _prepare_file_name
        assert _prepare_file_name(file_name) == expected_result
