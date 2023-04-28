import logging
from copy import copy
from pathlib import Path
from typing import List, Union, Optional
from re import match, compile, VERBOSE
from assemblyline_client import get_client
from assemblyline_client.submit import (
    read_toml,
    add_config_url,
    DEFAULT_CONFIG,
    DEFAULT_TOML_PATH,
)
from threading import Timer

VALID_LOG_LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]

# These are regular expressions used for parameter validation that the user supplies
IP_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
DOMAIN_REGEX = (
    r"(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+"
    r"(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?)"
)
URI_PATH = r"(?:[/?#]\S*)"
FULL_URI = f"^((?:(?:[A-Za-z]*:)?//)?(?:\\S+(?::\\S*)?@)?(?:{IP_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?){URI_PATH}?$"

DEFAULT_SERVICES = ["Static Analysis", "Extraction", "Networking", "Antivirus"]
RESERVED_CHARACTERS = [
    ".",
    "?",
    "+",
    "*",
    "|",
    "{",
    "}",
    "[",
    "]",
    "(",
    ")",
    '"',
    "\\",
    ":",
    "/",
    " ",
]

_VALID_UTF8 = compile(
    rb"""((?:
    [\x09\x0a\x20-\x7e]|             # 1-byte (ASCII excluding control chars).
    [\xc2-\xdf][\x80-\xbf]|          # 2-bytes (excluding overlong sequences).
    [\xe0][\xa0-\xbf][\x80-\xbf]|    # 3-bytes (excluding overlong sequences).
    [\xe1-\xec][\x80-\xbf]{2}|       # 3-bytes.
    [\xed][\x80-\x9f][\x80-\xbf]|    # 3-bytes (up to invalid code points).
    [\xee-\xef][\x80-\xbf]{2}|       # 3-bytes (after invalid code points).
    [\xf0][\x90-\xbf][\x80-\xbf]{2}| # 4-bytes (excluding overlong sequences).
    [\xf1-\xf3][\x80-\xbf]{3}|       # 4-bytes.
    [\xf4][\x80-\x8f][\x80-\xbf]{2}  # 4-bytes (up to U+10FFFF).
    )+)""",
    VERBOSE,
)


def init_logging(log_file) -> logging.Logger:
    # These are details related to the log file.
    logging.basicConfig(
        filename=log_file,
        filemode="a",
        format="%(asctime)s.%(msecs)d,%(name)s,%(levelname)s,%(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG,
    )
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    log = logging.getLogger(__name__)
    return log


def parse_args(args=None, al_incident=None):
    from sys import argv
    from argparse import ArgumentParser, SUPPRESS

    if al_incident is None:
        if "analyzer" in argv[0]:
            al_incident = "Analyzer"
        elif "downloader" in argv[0]:
            al_incident = "Downloader"
        elif "submitter" in argv[0]:
            al_incident = "Submitter"
        else:
            al_incident = None

    parser = ArgumentParser(
        description=f"Assemblyline Incident {al_incident or 'Manager'}"
    )

    if al_incident is None:
        subparsers = parser.add_subparsers(dest="incident_manager")
        p_analyze = subparsers.add_parser("analyzer", help="Analyzer")
        p_download = subparsers.add_parser("downloader", help="Downloader")
        p_submit = subparsers.add_parser("submitter", help="Submitter")
    else:
        p_analyze = p_download = p_submit = parser

    parser.add_argument(
        "--config",
        default=DEFAULT_TOML_PATH,
        help=f"Read options from the specified TOML file.",
    )
    parser.add_argument("--server", help="The target URL that hosts Assemblyline.")
    parser.add_argument("--url", dest="server", help=SUPPRESS)
    parser.add_argument(
        "--insecure", action="store_true", help="Ignore SSL errors (insecure!)"
    )
    parser.add_argument(
        "--do_not_verify_ssl", action="store_true", dest="insecure", help=SUPPRESS
    )
    parser.add_argument("--server_crt", help=SUPPRESS)
    parser.add_argument(
        "--server-crt",
        metavar='"/path/to/server.crt"',
        help=SUPPRESS,
    )

    parser.add_argument(
        "-u",
        "--user",
        metavar='"user"',
        help="Your Assemblyline account username.",
    )
    parser.add_argument("--username", dest="user", help=SUPPRESS)
    parser.add_argument(
        "-k",
        "--apikey",
        metavar='"MY_RANDOM_API_KEY"',
        help="A path to a file that contains only your Assemblyline account API key. "
        "NOTE that this API key requires write access.",
    )
    parser.add_argument(
        "-p", "--password", metavar='"MYPASSWORD"', help=SUPPRESS
    )  # help="Your Assemblyline account password."
    parser.add_argument(
        "--cert", metavar='"/path/to/pki.pem"', help=SUPPRESS
    )  # "A path to a file that contains only your Assemblyline user certificate."

    parser.add_argument(
        "--incident-num",
        help="The incident number that each file is associated with.",
    )
    parser.add_argument("--incident_num", help=SUPPRESS)
    parser.add_argument(
        "-t",
        "--is_test",
        action="store_true",
        help="A flag that indicates that you're running a test.",
    )

    if al_incident in (None, "Submitter"):
        p_submit.add_argument(
            "path", nargs="+", type=valid_path, help="Path to process."
        )
        p_submit.add_argument(
            "--classification",
            default="TLP:AMBER",
            help="TLP for the files in the path.",
        )
        p_submit.add_argument(
            "--ttl", default=30, help="Days before submissions are removed."
        )
        p_submit.add_argument(
            "--services", action="append", help="Assemblyline Service Selection."
        )
        parser.add_argument("--service_selection", help=SUPPRESS)
        p_submit.add_argument(
            "--resubmit-dynamic",
            action="store_true",
            help="Resubmit files over threshold (default 500).",
        )
        p_submit.add_argument(
            "-f",
            "--fresh",
            action="store_true",
            help="Resubmit files over threshold (default 500).",
        )
        p_submit.add_argument(
            "--alert", action="store_true", help="Generate alerts for this submission."
        )
        p_submit.add_argument(
            "--threads",
            type=int,
            default=0,
            help="Number of threads that will ingest files to Assemblyline.",
        )
        p_submit.add_argument(
            "--dedup-hashes",
            action="store_true",
            help="Generate alerts for this submission.",
        )
        p_submit.add_argument(
            "--priority",
            type=int,
            default=100,
            help="Generate alerts for this submission.",
        )

    if al_incident in (None, "Analyzer"):
        p_analyze.add_argument(
            "--min-score",
            type=int,
            help="The minimum score for files that we want to query from Assemblyline.",
        )

    if al_incident in (None, "Downloader"):
        p_download.add_argument(
            "--max-score",
            type=int,
            default=-1,
            help="The maximum score for files that we want to download from Assemblyline.",
        )
        p_download.add_argument(
            "--download-path",
            required=al_incident is not None,
            help="The path to the folder that we will download files to.",
        )
        p_download.add_argument(
            "--upload-path",
            help="The base path from which the files were ingested from on the compromised system.",
        )
        try:
            p_download.add_argument(
                "--threads",
                type=int,
                default=0,
                help="Number of threads that will download files from Assemblyline.",
            )
        except Exception:
            pass

    if args is not None:
        parsed_args = parser.parse_args(args)
    else:
        parsed_args = parser.parse_args()

    args_dict = vars(parsed_args)

    cfg = copy(DEFAULT_CONFIG)
    cfg["incident"] = {}
    config_path = args_dict.pop("config", None)
    if config_path is not None:
        try:
            cfg.update(read_toml(config_path=config_path))
        except FileNotFoundError as ex:
            if config_path != DEFAULT_TOML_PATH:
                raise ex

    set_cli_args(args_dict, cfg)

    if cfg["server"].get("url") is None:
        add_config_url(cfg["server"])

    # Validate auth is set
    user = cfg["auth"].get("user")
    apikey = cfg["auth"].get("apikey")
    password = cfg["auth"].get("password")
    cert = cfg["auth"].get("cert")

    if not (cert or (user and apikey) or (user and password)):
        parser.error(
            "Authentication API Key or user certificate path must be provided."
        )

    # validate incident is set
    incident_num = cfg["incident"].get("incident_num")
    if not incident_num:
        parser.error("Incident Number must be provided.")

    return cfg


def set_cli_args(args_dict, cfg):
    """Update dict with CLI parameters"""
    for key, value in args_dict.items():
        if value is None:
            # Skip unset argparse values
            continue
        elif key == "server":
            cfg["server"]["url"] = value
        elif key == "server_crt":
            cfg["server"]["cert"] = value
        elif key in ("user", "password", "apikey", "insecure", "cert"):
            if value is False and cfg.get('auth', {}).get(key) is not None:
                # Skip unset store_true values, if the config file has the value set
                continue
            cfg["auth"][key] = value
        else:
            if value is False and cfg.get('incident', {}).get(key) is not None:
                # Skip unset store_true values, if the config file has the value set
                continue
            cfg["incident"][key] = value


class Client:
    def __init__(self, log: logging.Logger, server: dict, auth: dict) -> None:
        self.al_client = None
        self._refresh_client(log, server, auth)

    def _refresh_client(self, log: logging.Logger, server: dict, auth: dict) -> None:
        print_and_log(
            log, "ADMIN,Refreshing the Assemblyline Client...,,", logging.DEBUG
        )
        self.al_client = get_al_client(log, server, auth)
        thr = Timer(
            1800,
            self._refresh_client,
            (server, auth, log),
        )
        thr.daemon = True
        thr.start()


def validate_parameters(
    log: logging.Logger, url: str, service_selection: Optional[str] = None
) -> List[str]:
    if not _validate_url(log, url):
        return []
    if service_selection in [None, "[]", "['']"]:
        return DEFAULT_SERVICES
    else:
        return _validate_service_selection(log, service_selection)


def _validate_url(log: logging.Logger, url: str) -> bool:
    if match(FULL_URI, url):
        return True
    else:
        print_and_log(log, f"ADMIN,Invalid URL {url}.,,", logging.ERROR)
        return False


def _validate_service_selection(
    log: logging.Logger, service_selection: str
) -> List[str]:
    services_selected = [s.strip() for s in service_selection.split(",")]
    for service_selected in services_selected:
        if not service_selected:
            print_and_log(
                log,
                f"ADMIN,Invalid service selected {service_selected} of {services_selected},,",
                logging.ERROR,
            )
            return []
    return services_selected


def print_and_log(log: logging.Logger, message: str, log_level: int):
    message = safe_str(message)

    if log_level not in VALID_LOG_LEVELS:
        raise ValueError(f"The log level {log_level} is not one of f{VALID_LOG_LEVELS}")

    if log_level == logging.DEBUG:
        log.debug(message)
    elif log_level == logging.INFO:
        log.info(message)
    elif log_level == logging.WARNING:
        log.warning(message)
    elif log_level == logging.ERROR:
        log.error(message)
    print(message)


def prepare_apikey(apikey: str) -> str:
    try:
        apikey_path = Path(apikey).expanduser().resolve()
        return apikey_path.read_text().strip()
    except FileNotFoundError:
        return apikey.strip()


# This code is from Assemblyline
# https://github.com/CybercentreCanada/assemblyline-base/blob/ae27b8a6c585/assemblyline/common/str_utils.py#L108
def safe_str(s, force_str=False) -> str:
    return _escape_str(s, reversible=False, force_str=force_str)


def _escape_str(s, reversible=True, force_str=False):
    if isinstance(s, bytes):
        return _escape_str_strict(s, reversible)
    elif not isinstance(s, str):
        if force_str:
            return str(s)
        return s

    try:
        return _escape_str_strict(
            s.encode("utf-16", "surrogatepass").decode("utf-16").encode("utf-8"),
            reversible,
        )
    except Exception:
        return _escape_str_strict(
            s.encode("utf-8", errors="backslashreplace"), reversible
        )


# Returns a string (str) with only valid UTF-8 byte sequences.
def _escape_str_strict(s: bytes, reversible=True) -> str:
    escaped = b"".join(
        [_escape(t, reversible) for t in enumerate(_VALID_UTF8.split(s))]
    )
    return escaped.decode("utf-8")


def _escape(t, reversible=True):
    if t[0] % 2:
        return t[1].replace(b"\\", b"\\\\") if reversible else t[1]
    else:
        return b"".join((b"\\x%02x" % x) for x in t[1])


def prepare_query_value(query_value: str) -> str:
    if any(reserved_char in query_value for reserved_char in RESERVED_CHARACTERS):
        query_value = query_value.translate(
            str.maketrans(
                {
                    reserved_char: f"\\{reserved_char}"
                    for reserved_char in RESERVED_CHARACTERS
                }
            )
        )
    return query_value


def get_al_client(log: logging.Logger, server: dict, auth: dict):
    # Create the Assemblyline Client

    # Parameter validation
    if not _validate_url(log, server.get("url")):
        return

    # No trailing forward slashes in the URL!
    server["url"] = server.get("url").rstrip("/")

    server_crt_or_verify = server.get("cert") or not auth.get("insecure")

    if auth.get("cert"):
        al_client = get_client(
            server.get("url"), cert=auth.get("cert"), verify=server_crt_or_verify
        )
    elif auth.get("password"):
        user_auth = (auth.get("user"), auth.get("password"))
        al_client = get_client(
            server.get("url"), auth=user_auth, verify=server_crt_or_verify
        )
    else:
        api_auth = (auth.get("user"), prepare_apikey(auth.get("apikey")))
        al_client = get_client(
            server.get("url"), apikey=api_auth, verify=server_crt_or_verify
        )
    return al_client


def valid_path(path_to_validate: Union[str, Path], type_enforce: str = None) -> Path:
    """
    Validate path. Set type_enforce value to "dir" or "file" to enforce the type.
    """
    path = Path(path_to_validate)
    if path.exists():
        if type_enforce is None:
            return path
        if type_enforce == "dir" and path.is_dir():
            return path
        if type_enforce == "file" and path.is_file():
            return path
    raise ValueError
