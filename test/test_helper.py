import pytest


@pytest.fixture
def log():
    import logging

    log = logging.getLogger(__name__)
    return log


class TestHelper:
    @staticmethod
    def test_init_logging():
        from assemblyline_incident_manager.helper import init_logging

        init_logging("blah.blah")
        assert True

    @staticmethod
    @pytest.mark.parametrize(
        "url, service_selection, expected_result",
        [
            ("http://blah.com", "Extract,Cuckoo", ["Extract", "Cuckoo"]),
            ("not a url", "Extract,Cuckoo", []),
            ("http://blah.com", "Extract,", []),
            (
                "http://blah.com",
                None,
                ["Static Analysis", "Extraction", "Networking", "Antivirus"],
            ),
        ],
    )
    def test_validate_parameters(url, service_selection, expected_result, log):
        from assemblyline_incident_manager.helper import validate_parameters

        assert validate_parameters(log, url, service_selection) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "services, expected_result",
        [
            ("Extract,Cuckoo", ["Extract", "Cuckoo"]),
            ("Extract,", []),
            ("Extract", ["Extract"]),
        ],
    )
    def test_validate_service_selection(services, expected_result, log):
        from assemblyline_incident_manager.helper import _validate_service_selection

        assert _validate_service_selection(log, services) == expected_result

    @staticmethod
    @pytest.mark.parametrize(
        "url, expected_result", [("http://blah.com", True), ("not a url", False)]
    )
    def test_validate_url(url, expected_result, log):
        from assemblyline_incident_manager.helper import _validate_url

        assert _validate_url(log, url) == expected_result

    @staticmethod
    @pytest.mark.parametrize("log_level", [10, 20, 30, 40, 15])
    def test_print_and_log(log_level, log):
        from assemblyline_incident_manager.helper import print_and_log, VALID_LOG_LEVELS

        illegal_surrogate_string = "blah blah blah \ud83d.txt"
        normal_string = "blah blah blah.txt"

        if log_level not in VALID_LOG_LEVELS:
            with pytest.raises(ValueError):
                print_and_log(log, illegal_surrogate_string, log_level)
                print_and_log(log, normal_string, log_level)
        else:
            print_and_log(log, illegal_surrogate_string, log_level)
            print_and_log(log, normal_string, log_level)
            assert True

    @staticmethod
    @pytest.mark.parametrize(
        "value, expected_result",
        [
            ("blahblahblah", "blahblahblah"),
            (
                "v4:akfkP426PLuy$1X4nDKjY3*y9FblahUs&Uii?r8k2pnq@sN?^",
                "v4:akfkP426PLuy$1X4nDKjY3*y9FblahUs&Uii?r8k2pnq@sN?^",
            ),
            (
                "v4:akfkP426PLblah4nDKjY3*y9FxHMhU!s&Uii?r8k2pnq@sN?^\n",
                "v4:akfkP426PLblah4nDKjY3*y9FxHMhU!s&Uii?r8k2pnq@sN?^",
            ),
            (
                "v4:akfkP426PL?uy1X4nDKjY3*y9blahUs&Uii?r8k2pnq@sN?^\r",
                "v4:akfkP426PL?uy1X4nDKjY3*y9blahUs&Uii?r8k2pnq@sN?^",
            ),
            (
                "\nv4:akfkP426PLuy1X4nDKjY3*y9FxHMhUs&Ui\i?r8k2pnq@sN?^\r",
                "v4:akfkP426PLuy1X4nDKjY3*y9FxHMhUs&Ui\\i?r8k2pnq@sN?^",
            ),
            (
                "v3fkP426PLuy1blahY3*y9FxHMhUs&Uii?r8k2pnq@sN?^",
                "v3fkP426PLuy1blahY3*y9FxHMhUs&Uii?r8k2pnq@sN?^",
            ),
        ],
    )
    def test_prepare_apikey(value, expected_result):
        from os import remove
        from assemblyline_incident_manager.helper import prepare_apikey

        apikey_bytes_path = "apikey_path_bytes.txt"
        apikey_path = "apikey_path.txt"
        with open(apikey_bytes_path, "wb") as f:
            f.write(value.encode())
        with open(apikey_path, "w") as f:
            f.write(value)
        assert prepare_apikey(apikey_path) == expected_result
        assert prepare_apikey(apikey_bytes_path) == expected_result
        remove(apikey_bytes_path)
        remove(apikey_path)

    @staticmethod
    def test_safe_str():
        from assemblyline_incident_manager.helper import safe_str

        assert safe_str("hello") == "hello"
        assert safe_str("hello\x00") == "hello\\x00"
        assert safe_str("\xf1\x90\x80\x80") == "\xf1\x90\x80\x80"
        assert safe_str("\xc2\x90") == "\xc2\x90"
        assert safe_str("\xc1\x90") == "\xc1\x90"

    @staticmethod
    @pytest.mark.parametrize(
        "val, expected_result",
        [
            ("blah", "blah"),
            ("bl.ah", "bl\.ah"),
            ("bl?ah", "bl\?ah"),
            ("bl+ah", "bl\+ah"),
            ("bl*ah", "bl\*ah"),
            ("bl|ah", "bl\|ah"),
            ("bl{ah", "bl\{ah"),
            ("bl}ah", "bl\}ah"),
            ("bl[ah", "bl\[ah"),
            ("bl]ah", "bl\]ah"),
            ("bl(ah", "bl\(ah"),
            ("bl)ah", "bl\)ah"),
            ('bl"ah', 'bl\\"ah'),
            ("bl\\ah", "bl\\\\ah"),
        ],
    )
    def test_prepare_query_value(val, expected_result):
        from assemblyline_incident_manager.helper import prepare_query_value

        assert prepare_query_value(val) == expected_result
