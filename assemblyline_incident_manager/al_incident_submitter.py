"""
This file contains the code that does the "pushing". It submits all of the files that the  user
wants to have submitted to Assemblyline for analysis.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import click
import logging
import os
from hashlib import sha256
from typing import List
from time import sleep, time
from threading import Thread
from queue import Queue

from assemblyline_client import Client4
from assemblyline_incident_manager.helper import init_logging, print_and_log, validate_parameters, prepare_apikey, safe_str, Client, prepare_query_value

# These are the names of the files which we will use for writing and reading information to
# This contains the logs for this file
LOG_FILE = "al_incident_submitter_log.csv"
# This contains the file paths of every file ingested
FILE_PATHS = "file_paths.txt"
# This contains just the file paths that failed to be ingested. This can be used with the ingest_skipped script.
SKIPPED_FILE_PATHS = "skipped_files.txt"
# This contains a test file
TEST_FILE = "test.txt"

# Create file handlers for the information files we need.
FILE_PATHS_WRITER = open(FILE_PATHS, "a+", encoding='utf-8')
SKIPPED_FILE_PATHS_WRITER = open(SKIPPED_FILE_PATHS, "a+", encoding='utf-8')

# These are the max and min size of files able to be submitted to Assemblyline, in bytes
MAX_FILE_SIZE = 100000000
MIN_FILE_SIZE = 1

log = init_logging(LOG_FILE)

# Globals
hash_table = []
number_of_files_ingested = 0
number_of_files_skipped = 0
number_of_file_duplicates = 0
number_of_files_greater_than_max_size = 0
number_of_files_less_than_min_size = 0
total_file_count = 0


def get_id_from_data(file_path: str) -> str:
    """
    This method generates a sha256 hash for the file contents of a file
    @param file_path: The file path
    @return _hash: The sha256 hash of the file
    """
    sha256_hash = sha256()
    # stream it in so we don't load the whole file in memory
    with open(file_path, 'rb') as f:
        data = f.read(4096)
        while data:
            sha256_hash.update(data)
            data = f.read(4096)
    return sha256_hash.hexdigest()


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("--username", required=True, type=click.STRING,  help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.Path(exists=True, readable=True),
              help="A path to a file that contains only your Assemblyline account API key. NOTE that this API key requires write access.")
@click.option("--ttl", type=click.INT, default=30,
              help="The amount of time that you want your Assemblyline submissions to live on the Assemblyline system (in days).")
@click.option("--classification", required=True, type=click.STRING,
              help="The classification level for each file submitted to Assemblyline.")
@click.option("--service_selection", required=False, type=click.STRING,
              help="A comma-separated list (no spaces!) of service names (case-sensitive) to send files to. If not provided, all services will be selected.")
@click.option("-t", "--is_test", is_flag=True, help="A flag that indicates that you're running a test.")
@click.option("--path", required=True, type=click.Path(exists=True, readable=True),
              help="The directory path containing files that you want to submit to Assemblyline.")
@click.option("-f", "--fresh", is_flag=True, help="Restart ingestion from the beginning.")
@click.option("--incident_num", required=True, type=click.STRING,
              help="The incident number for each file to be associated with.")
@click.option("--resubmit-dynamic", is_flag=True,
              help="All files that score higher than 500 will be resubmitted for dynamic analysis.")
@click.option("--alert", is_flag=True, help="Generate alerts for this submission.")
@click.option("--threads", default=0, type=click.INT, help="Number of threads that will ingest files to Assemblyline.")
@click.option("--dedup_hashes", is_flag=True,
              help="Only submit files with unique hashes. If you want 100% file coverage in a given path, do not use this flag")
@click.option("--priority", default=100, required=False, type=click.INT,
              help="Provide a priority number which will cause the ingestion to go to a specific priority queue.")
@click.option("--do_not_verify_ssl", is_flag=True, help="Ignore SSL errors (insecure!)")
def main(url: str, username: str, apikey: str, ttl: int, classification: str, service_selection: str, is_test: bool, path: str, fresh: bool, incident_num: str, resubmit_dynamic: bool, alert: bool, threads: int, dedup_hashes: bool, priority: int, do_not_verify_ssl: bool):
    """
    Example:
    al-incident_submitter --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="/path/to/file/containing/apikey" --classification="<classification>" --service_selection="<service-name>,<service-name>" --path="/path/to/scan" --incident_num=123
    """
    global hash_table
    global total_file_count

    apikey_val = prepare_apikey(apikey)

    # Parameter validation
    incident_num = prepare_query_value(incident_num)
    service_selection = validate_parameters(log, url, service_selection)
    if not service_selection:
        return

    # Setting the parameters
    settings = _generate_settings(ttl, classification, service_selection, resubmit_dynamic, priority)

    # Confirm that given path is to a directory
    if not os.path.isdir(path):
        print_and_log(log, f"INFO,Provided path {path} points to a file, but it should point to a directory.", logging.DEBUG)
        return

    if is_test:
        # Create the Assemblyline Client
        al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client
        _test_ingest_file(al_client, settings, incident_num, alert)
        return

    if fresh:
        _freshen_up()

    file_count = 0

    # Script Resumption Logic
    # If the script somehow crashed or stopped prematurely, then the text file containing
    # the file_paths which have been ingested to Assemblyline will still exist on the host.
    # Therefore, we will check if that file exists, and if so, then we will grab the last
    # file_path that has been ingested to Assemblyline and use that as our starting point for
    # the current run.
    skip, resume_ingestion_path = _get_most_recent_file_path()

    skipped_file_paths = []
    # If we are resuming, then we will need to know what files failed to be ingested the first time around
    if os.path.exists(SKIPPED_FILE_PATHS):
        with open(SKIPPED_FILE_PATHS, "r", encoding='utf-8') as f:
            contents = f.readlines()
            skipped_file_paths = [content.strip() for content in filter(None, contents)]
        with open(SKIPPED_FILE_PATHS, "w") as f:
            # Now that we have the files that failed to be ingested, reset the file!
            f.write("")

    # Get the number of files in folder, so that we can provide
    print_and_log(log, "INFO,Generating the number of files which we will be submitting...", logging.DEBUG)
    for root, _, files in os.walk(path):
        l = len(files)
        if l:
            total_file_count += l
    print_and_log(log, f"INFO,Number of files which we will be submitting: {total_file_count}", logging.DEBUG)

    if threads == 0:
        # From https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor
        max_workers = min(32, os.cpu_count() + 4)
    else:
        max_workers = threads

    if max_workers > total_file_count:
        max_workers = total_file_count

    workers = []
    file_queue = Queue()

    for _ in range(max_workers):
        # Creating a thread containing a unique AL client
        al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client

        worker = Thread(target=_thr_queue_reader,
                        args=(file_queue, al_client),
                        daemon=True)
        workers.append(worker)

    # Start em up!
    for worker in workers:
        worker.start()

    start_time = time()
    # Recursively go through every file in the provided folder and its sub-folders.
    for root, _, file_names in os.walk(path):
        if not len(file_names):
            continue
        for file_name in file_names:
            file_count += 1
            file_path = os.path.join(root, file_name)
            prepared_file_path = safe_str(file_path)
            # This happens in Windows when the file path is too long https://stackoverflow.com/questions/1365797/python-long-filename-support-broken-in-windows
            if not os.path.exists(file_path):
                file_path = f"\\\\?\\{file_path}"

            # We only care about files that occur after the last sha in the hash file
            if resume_ingestion_path:
                if prepared_file_path in skipped_file_paths:
                    print_and_log(log, f"INFO,Found a skipped file path {prepared_file_path}. Trying to ingest again!,{prepared_file_path},",
                                  logging.DEBUG)
                    file_queue.put((file_path, prepared_file_path, settings, incident_num, alert, file_count, dedup_hashes, True))
                    continue
                elif resume_ingestion_path == prepared_file_path:
                    print_and_log(log, f"INFO,Found the most recently submitted file path {resume_ingestion_path},{prepared_file_path},",
                                  logging.DEBUG)
                    skip = False

            # If we have yet to come up to the file who matches the last submitted file path, continue looking!
            if skip:
                print_and_log(log,
                              f"INFO,Seeking the file that matches this file path: {resume_ingestion_path}. {prepared_file_path} has already been ingested.,{prepared_file_path},",
                              logging.DEBUG)
                continue
            file_queue.put((file_path, prepared_file_path, settings, incident_num, alert, file_count, dedup_hashes, False))

    while file_queue.qsize():
        sleep(1)

    for _ in range(max_workers):
        file_queue.put("DONE")

    # Time to clock out!
    for worker in workers:
        worker.join()

    print_and_log(log, f"INFO,Ingestion Complete", logging.DEBUG)
    print_and_log(log, f"INFO,Number of files ingested = {number_of_files_ingested}", logging.DEBUG)
    print_and_log(log, f"INFO,Number of duplicate files on system = {number_of_file_duplicates}", logging.DEBUG)
    print_and_log(log, f"INFO,Number of files skipped due to errors = {number_of_files_skipped}", logging.DEBUG)
    print_and_log(log, f"INFO,Number of files with size greater than {MAX_FILE_SIZE}B = {number_of_files_greater_than_max_size}", logging.DEBUG)
    print_and_log(log, f"INFO,Number of files with size less than {MIN_FILE_SIZE}B = {number_of_files_less_than_min_size}", logging.DEBUG)
    print_and_log(log, f"INFO,Total time elapsed: {round(time() - start_time, 3)}s", logging.DEBUG)


def _generate_settings(ttl: int, classification: str, service_selection: List[str], resubmit_dynamic: bool, priority: int) -> dict:
    settings = {
        "ttl": ttl,
        "classification": classification,
        "services": {
            "selected": service_selection,
            "resubmit": ["Dynamic Analysis"] if resubmit_dynamic else []
        },
        "priority": priority  # Note that the lower the priority queue, the larger the maximum queue size.
    }
    return settings


def _freshen_up():
    if os.path.exists(FILE_PATHS):
        try:
            os.remove(FILE_PATHS)
        except PermissionError:
            # This is a work-around to multi-threading in a Windows environment
            with open(FILE_PATHS, "w") as f:
                f.write("")
    if os.path.exists(SKIPPED_FILE_PATHS):
        try:
            os.remove(SKIPPED_FILE_PATHS)
        except PermissionError:
            # This is a work-around to multi-threading in a Windows environment
            with open(SKIPPED_FILE_PATHS, "w") as f:
                f.write("")


def _file_has_valid_size(file_path: str, prepared_file_path: str) -> (bool, int, int):
    file_size = os.path.getsize(file_path)
    max_count = 0
    min_count = 0
    if file_size > MAX_FILE_SIZE:
        print_and_log(log, f"TOO_LARGE,{prepared_file_path} is too big. Size: {file_size} > {MAX_FILE_SIZE}.,{prepared_file_path},", logging.DEBUG)
        max_count += 1
        return False, max_count, min_count
    elif file_size < MIN_FILE_SIZE:
        print_and_log(log, f"TOO_SMALL,{prepared_file_path} is too small. Size: {file_size} < {MIN_FILE_SIZE}.,{prepared_file_path},", logging.DEBUG)
        min_count += 1
        return False, max_count, min_count
    else:
        return True, max_count, min_count


def _test_ingest_file(al_client: Client4, settings: dict, incident_num: str, alert: bool):
    print_and_log(log, f"INFO,The Assemblyline ingest settings you using are: {settings}", logging.DEBUG)

    # Create randomly generated buffer to test the submission parameters
    file_contents = os.urandom(100)
    with open(TEST_FILE, "wb") as f:
        f.write(file_contents)

    sha = get_id_from_data(TEST_FILE)

    # Ingesting the test file
    print_and_log(log, f"INGEST,{TEST_FILE} ({sha}) is about to be ingested in test mode.,{TEST_FILE},{sha}", logging.DEBUG)
    al_client.ingest(path=TEST_FILE, fname=TEST_FILE, params=settings, alert=alert, metadata={"filename": TEST_FILE, "incident_number": incident_num})
    print_and_log(log, f"INGEST,{TEST_FILE} ({sha}) has been ingested in test mode.,{TEST_FILE},{sha}", logging.DEBUG)

    os.remove(TEST_FILE)


def _ingest_file(file_path: str, prepared_file_path: str, sha: str, al_client: Client4, settings: dict, incident_num: str, alert: bool):
    print_and_log(log, f"INGEST,{prepared_file_path} ({sha}) is about to be ingested.,{prepared_file_path},{sha}", logging.DEBUG)
    al_client.ingest(path=file_path, fname=sha, params=settings, alert=alert, metadata={"filename": file_path, "incident_number": incident_num})
    print_and_log(log, f"INGEST,{prepared_file_path} ({sha}) has been ingested.,{prepared_file_path},{sha}", logging.DEBUG)


def _get_most_recent_file_path() -> (bool, str):
    global hash_table
    if not os.path.exists(FILE_PATHS) or not os.path.getsize(FILE_PATHS):
        return False, None

    with open(FILE_PATHS, 'rb') as fh:
        # First check if there is only one line in the file
        line = fh.readline()
        if not fh.readline():
            # Confirmed, only one line
            file_path = line.decode().strip("\n")
        else:
            fh.seek(-2, os.SEEK_END)
            # We want to find the last newline above the line that we want.
            while fh.read(1) != b'\n':
                fh.seek(-2, os.SEEK_CUR)

            # We found it, read the entire last line, this is our hash
            file_path = fh.readline().decode().strip("\n\r")

    # This adds the most recent hash that has been ingested to the hash table, so that
    # we do not re-ingest it during this run.
    sha = get_id_from_data(file_path)
    hash_table.append(sha)
    return True, file_path


def _thr_ingest_file(
        file_path: str,
        prepared_file_path: str,
        al_client: Client4,
        settings: dict,
        incident_num: str,
        alert: bool,
        file_count: int,
        dedup_hashes: bool,
        was_skipped: bool,
):
    global number_of_files_greater_than_max_size
    global number_of_files_less_than_min_size
    global number_of_files_ingested
    global number_of_files_skipped
    global number_of_file_duplicates
    global hash_table

    # Print the counts every 100 files
    if file_count % 100 == 0:
        print_and_log(log, f"INFO,Number of files ingested = {number_of_files_ingested}", logging.DEBUG)
        print_and_log(log, f"INFO,Number of duplicate files on system = {number_of_file_duplicates}", logging.DEBUG)
        print_and_log(log, f"INFO,Number of files skipped due to errors = {number_of_files_skipped}", logging.DEBUG)
        print_and_log(log, f"INFO,Number of files with size greater than {MAX_FILE_SIZE}B = {number_of_files_greater_than_max_size}", logging.DEBUG)
        print_and_log(log, f"INFO,Number of files with size less than {MIN_FILE_SIZE}B = {number_of_files_less_than_min_size}", logging.DEBUG)
        print_and_log(log, f"INFO,Progress = {round((file_count / total_file_count) * 100, 2)}%", logging.DEBUG)

    sha = None
    # Wrap everything in a try-catch so we become invincible
    try:
        file_size_is_valid, size_is_too_big, size_is_too_small = _file_has_valid_size(file_path, prepared_file_path)
        if not file_size_is_valid:
            number_of_files_greater_than_max_size += size_is_too_big
            number_of_files_less_than_min_size += size_is_too_small
            return

        # Create a sha256 hash using the file contents.
        sha = get_id_from_data(file_path)

        # If hash has already been submitted, then skip it
        if dedup_hashes and sha in hash_table:
            print_and_log(log, f"DUPLICATE,{prepared_file_path} ({sha}) is a duplicate file. Skipping!,{prepared_file_path},{sha}", logging.DEBUG)
            number_of_file_duplicates += 1
            return

        # Ingestion and logging everything
        _ingest_file(file_path, prepared_file_path, sha, al_client, settings, incident_num, alert)
        hash_table.append(sha)

        # Documenting the hash into the text file
        number_of_files_ingested += 1
        if not was_skipped:
            FILE_PATHS_WRITER.write(f"{prepared_file_path}\n")

    except Exception as e:
        print_and_log(log, f"SKIP,{prepared_file_path} was skipped due to {e}.,{prepared_file_path},{sha}", logging.ERROR)
        number_of_files_skipped += 1
        SKIPPED_FILE_PATHS_WRITER.write(f"{prepared_file_path}\n")


def _thr_queue_reader(queue: Queue, al_client: Client4) -> None:
    while True:
        msg = queue.get()
        if msg == "DONE":
            return
        else:
            file_path, prepared_file_path, settings, incident_num, alert, file_count, dedup_hashes, was_skipped = msg
            _thr_ingest_file(file_path, prepared_file_path, al_client, settings, incident_num, alert, file_count, dedup_hashes, was_skipped)


if __name__ == "__main__":
    main()
