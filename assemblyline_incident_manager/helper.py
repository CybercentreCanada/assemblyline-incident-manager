import logging
from typing import List, Optional
from re import match, compile, VERBOSE
from assemblyline_client import get_client
from threading import Timer

VALID_LOG_LEVELS = [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]

# These are regular expressions used for parameter validation that the user supplies
IP_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
DOMAIN_REGEX = r"(?:(?:[A-Za-z0-9\u00a1-\uffff][A-Za-z0-9\u00a1-\uffff_-]{0,62})?[A-Za-z0-9\u00a1-\uffff]\.)+" \
               r"(?:xn--)?(?:[A-Za-z0-9\u00a1-\uffff]{2,}\.?)"
URI_PATH = r"(?:[/?#]\S*)"
FULL_URI = f"^((?:(?:[A-Za-z]*:)?//)?(?:\\S+(?::\\S*)?@)?(?:{IP_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?){URI_PATH}?$"

DEFAULT_SERVICES = ["Static Analysis", "Extraction", "Networking", "Antivirus"]
RESERVED_CHARACTERS = [".", "?", "+", "*", "|", "{", "}", "[", "]", "(", ")", '"', "\\", ":", "/", " "]

_VALID_UTF8 = compile(rb"""((?:
    [\x09\x0a\x20-\x7e]|             # 1-byte (ASCII excluding control chars).
    [\xc2-\xdf][\x80-\xbf]|          # 2-bytes (excluding overlong sequences).
    [\xe0][\xa0-\xbf][\x80-\xbf]|    # 3-bytes (excluding overlong sequences).
    [\xe1-\xec][\x80-\xbf]{2}|       # 3-bytes.
    [\xed][\x80-\x9f][\x80-\xbf]|    # 3-bytes (up to invalid code points).
    [\xee-\xef][\x80-\xbf]{2}|       # 3-bytes (after invalid code points).
    [\xf0][\x90-\xbf][\x80-\xbf]{2}| # 4-bytes (excluding overlong sequences).
    [\xf1-\xf3][\x80-\xbf]{3}|       # 4-bytes.
    [\xf4][\x80-\x8f][\x80-\xbf]{2}  # 4-bytes (up to U+10FFFF).
    )+)""", VERBOSE)


def init_logging(log_file) -> logging.Logger:
    # These are details related to the log file.
    logging.basicConfig(
        filename=log_file,
        filemode="a",
        format='%(asctime)s.%(msecs)d,%(name)s,%(levelname)s,%(message)s',
        datefmt='%H:%M:%S',
        level=logging.DEBUG
    )
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    log = logging.getLogger(__name__)
    return log


class Client:
    def __init__(self, log: logging.Logger, url: str, username: str, apikey: str, do_not_verify_ssl: bool) -> None:
        self.al_client = None
        self._thr_refresh_client(log, url, username, apikey, do_not_verify_ssl)

    def _thr_refresh_client(
            self, log: logging.Logger, url: str, username: str, apikey: str, do_not_verify_ssl: bool) -> None:
        print_and_log(log, "ADMIN,Refreshing the Assemblyline Client...,,", logging.DEBUG)
        self.al_client = get_client(url, apikey=(username, apikey), verify=not do_not_verify_ssl)
        thr = Timer(1800, self._thr_refresh_client, (log, url, username, apikey, do_not_verify_ssl))
        thr.daemon = True
        thr.start()


def validate_parameters(log: logging.Logger, url: str, service_selection: Optional[str] = None) -> List[str]:
    if not _validate_url(log, url):
        return []
    if service_selection in [None, '[]', "['']"]:
        return DEFAULT_SERVICES
    else:
        return _validate_service_selection(log, service_selection)


def _validate_url(log: logging.Logger, url: str) -> bool:
    if match(FULL_URI, url):
        return True
    else:
        print_and_log(log, f"ADMIN,Invalid URL {url}.,,", logging.ERROR)
        return False


def _validate_service_selection(log: logging.Logger, service_selection: str) -> List[str]:
    services_selected = service_selection.split(",")
    for service_selected in services_selected:
        if not service_selected:
            print_and_log(
                log, f"ADMIN,Invalid service selected {service_selected} of {services_selected},,", logging.ERROR)
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


def prepare_apikey(apikey_path: str) -> str:
    with open(apikey_path, "rb") as f:
        contents = f.read()
        stripped_contents = contents.strip()
        return stripped_contents.decode()


# This code is from Assemblyline https://github.com/CybercentreCanada/assemblyline-base/blob/ae27b8a6c585a738573f7099dcde83fc5b3e36ee/assemblyline/common/str_utils.py#L108
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
        return _escape_str_strict(s.encode('utf-16', 'surrogatepass').decode('utf-16').encode('utf-8'), reversible)
    except Exception:
        return _escape_str_strict(s.encode('utf-8', errors="backslashreplace"), reversible)


# Returns a string (str) with only valid UTF-8 byte sequences.
def _escape_str_strict(s: bytes, reversible=True) -> str:
    escaped = b''.join([_escape(t, reversible)
                        for t in enumerate(_VALID_UTF8.split(s))])
    return escaped.decode('utf-8')


def _escape(t, reversible=True):
    if t[0] % 2:
        return t[1].replace(b'\\', b'\\\\') if reversible else t[1]
    else:
        return b''.join((b'\\x%02x' % x) for x in t[1])


def prepare_query_value(query_value: str) -> str:
    if any(reserved_char in query_value for reserved_char in RESERVED_CHARACTERS):
        query_value = query_value.translate(str.maketrans(
            {reserved_char: f"\\{reserved_char}"
             for reserved_char in RESERVED_CHARACTERS}))
    return query_value
