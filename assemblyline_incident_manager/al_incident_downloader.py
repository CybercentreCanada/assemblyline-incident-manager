"""
This file contains the code that does the "pulling". It requests all of the files that the user
has submitted to Assemblyline for analysis via the "pusher".

The difference between this file and the results_analyzer.py is that this file is mainly about retrieving
files that are under a certain score threshold according to Assemblyline, and building a directory containing
these files.

There are 4 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import logging
import click
import os
from time import time, sleep
from threading import Thread
from queue import Queue

from assemblyline_client import Client4
from assemblyline_incident_manager.helper import init_logging, print_and_log, _validate_url, prepare_apikey, prepare_query_value, Client

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "directory_downloader_log.csv"

log = init_logging(LOG_FILE)

# Global
total_downloaded = 0


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("-u", "--username", required=True, type=click.STRING, help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.Path(exists=True, readable=True),
              help="A path to a file that contains only your Assemblyline account API key. NOTE that this API key requires read access.")
@click.option("--max_score", required=True, default=1, type=click.INT,
              help="The maximum score for files that we want to download from Assemblyline.")
@click.option("--incident_num", required=True, type=click.STRING,
              help="The incident number that each file is associated with.")
@click.option("--download_path", required=True, type=click.Path(exists=False),
              help="The path to the folder that we will download files to.")
@click.option("--upload_path", required=True, type=click.Path(exists=False),
              help="The base path from which the files were ingested from on the compromised system.")
@click.option("-t", "--is_test", is_flag=True, help="A flag that indicates that you're running a test.")
@click.option("--num_of_downloaders", default=1, type=click.INT,
              help="The number of threads that will be created to facilitate downloading the files.")
@click.option("--do_not_verify_ssl", is_flag=True, help="Verify SSL when creating and using the Assemblyline Client.")
def main(url: str, username: str, apikey: str, max_score: int, incident_num: str, download_path: str, upload_path,
         is_test: bool, num_of_downloaders: int, do_not_verify_ssl: bool):
    """
    Example:
    al-incident-downloader --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="/path/to/file/containing/apikey" --incident_num=123 --min_score=100 --download_path=/path/to/where/you/want/downloads --upload_path=/path/from/where/files/were/uploaded/from
    """
    # Here is the query that we will be using to retrieve all submission details
    incident_num = prepare_query_value(incident_num)
    prepared_upload_path = prepare_query_value(upload_path)
    query = f"metadata.incident_number:\"{incident_num}\" AND max_score:<={max_score} AND metadata.filename:*{prepared_upload_path}*"

    if is_test:
        print_and_log(log, f"INFO,The query that you will make is: {query}.", logging.DEBUG)
        print_and_log(log, f"INFO,The files you are querying were uploaded from: {upload_path}.", logging.DEBUG)
        print_and_log(log, f"INFO,The files you are querying are to be downloaded to: {download_path}.", logging.DEBUG)
        return
    else:
        print_and_log(log, f"INFO,Query: {query}.", logging.DEBUG)

    # First check if the download path exists
    if not os.path.exists(download_path):
        os.mkdir(download_path)
        overwrite_all = True
        add_unique = True
    else:
        overwrite_all, add_unique = _handle_overwrite(download_path)

    if not overwrite_all and not add_unique:
        return

    # Parameter validation
    if not _validate_url(log, url):
        return

    # No trailing forward slashes in the URL!
    url = url.rstrip("/")

    apikey_val = prepare_apikey(apikey)

    # Create the Assemblyline Client
    al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client

    # Create a generator that yields the SIDs for our query
    submission_res = al_client.search.stream.submission(query, fl="sid")
    sids = []

    print_and_log(log, f"INFO,Gathering the submission IDs.", logging.DEBUG)
    for submission in submission_res:
        sid = submission["sid"]
        sids.append(sid)
    print_and_log(log, f"INFO,There are {len(sids)} submission IDs.", logging.DEBUG)

    total_already_downloaded = 0
    for root, dir, files in os.walk(download_path):
        total_already_downloaded += len(files)

    entered = False
    file_queue = Queue()
    workers = []

    for _ in range(num_of_downloaders):
        # Creating a thread containing a unique AL client
        al_client = Client(log, url, username, apikey_val, do_not_verify_ssl).al_client

        worker = Thread(target=_thr_queue_reader,
                        args=(file_queue, al_client),
                        daemon=True)
        workers.append(worker)

    # Start em up!
    for worker in workers:
        worker.start()

    total_submissions_that_match_query = len(sids)
    unique_file_paths = set()
    unique_file_hashes = set()
    start_time = time()
    while not entered or not all(al_client.submission.is_completed(sid) for sid in sids):
        entered = True
        for sid in sids[:]:
            if not al_client.submission.is_completed(sid):
                continue
            else:
                sids.remove(sid)

            # Deep dive into the submission to get the files
            submission_details = al_client.submission(sid)
            submitted_filepath = submission_details["metadata"]["filename"]
            file_hash = submission_details["files"][0]["sha256"]
            unique_file_paths.add(submitted_filepath)
            unique_file_hashes.add(file_hash)

            if upload_path not in submitted_filepath:
                print_and_log(
                    log,
                    f"INFO,{upload_path} is not in {submitted_filepath} for SID {sid} even though it shares the provided incident number {incident_num}.,{submitted_filepath},{file_hash}",
                    log_level=logging.DEBUG)
                continue
            root_filepath = submitted_filepath.replace(upload_path, "")
            root_filepath = root_filepath.lstrip("\\")
            root_filepath = root_filepath.lstrip("/")
            filepath_to_download = os.path.join(download_path, root_filepath)
            os.makedirs(os.path.dirname(filepath_to_download), exist_ok=True)

            if not overwrite_all and add_unique:
                if os.path.exists(filepath_to_download):
                    print_and_log(
                        log,
                        f"INFO,{filepath_to_download} has already been downloaded.,{submitted_filepath},{file_hash}",
                        log_level=logging.DEBUG)
                    continue

            file_queue.put((file_hash, filepath_to_download))

    while file_queue.qsize():
        print_and_log(log, "INFO,Waiting for the queue to empty...", logging.DEBUG)
        sleep(1)

    for _ in range(num_of_downloaders):
        file_queue.put("DONE")

    # Time to clock out!
    for worker in workers:
        worker.join()

    print_and_log(log, f"INFO,Download complete!", logging.DEBUG)
    print_and_log(
        log,
        f"INFO,{len(unique_file_paths)} unique file paths found in {total_submissions_that_match_query} submissions that match the query.",
        logging.DEBUG)
    print_and_log(
        log,
        f"INFO,{len(unique_file_hashes)} files with unique contents found in {total_submissions_that_match_query} submissions that match the query.",
        logging.DEBUG)
    print_and_log(
        log, f"INFO,{total_already_downloaded} files were downloaded to {download_path} in previous runs.", logging.DEBUG)
    print_and_log(log, f"INFO,{total_downloaded} files downloaded to {download_path} in current run.", logging.DEBUG)
    print_and_log(log, f"INFO,Total elapsed time: {time() - start_time}.", logging.DEBUG)
    print_and_log(log, "INFO,Thank you for using Assemblyline :)", logging.DEBUG)


def _handle_overwrite(download_dir: str) -> (bool, bool):
    overwrite_all = False
    add_unique = False
    overwrite = input(
        f"The download directory {download_dir} already exists. Do you wish to overwrite all contents? [y/n]:")
    if overwrite == "y":
        overwrite_all = True
    elif overwrite == "n":
        add_missing = input(
            f"The download directory {download_dir} already exists. Do you wish to download additional files to this directory? [y/n]:")
        if add_missing == "y":
            add_unique = True
        elif add_missing == "n":
            print_and_log(
                log,
                f"INFO,The download directory {download_dir} already exists. You chose not to download additional files and to exit.",
                logging.DEBUG)
        else:
            print_and_log(log, "INFO,You submitted a value that was neither [y/n]. Exiting.", logging.DEBUG)
    else:
        print_and_log(log, "INFO,You submitted a value that was neither [y/n]. Exiting.", logging.DEBUG)
    return overwrite_all, add_unique


def _thr_queue_reader(file_queue: Queue, al_client: Client4) -> None:
    global total_downloaded
    while True:
        msg = file_queue.get()
        if msg == "DONE":
            return
        else:
            sha, download_path = msg
            file_contents = al_client.file.download(sha, encoding="raw")
            with open(download_path, "wb") as f:
                f.write(file_contents)
            print_and_log(log, f"INFO,Downloaded {download_path}.,{download_path},{sha}", logging.DEBUG)
            total_downloaded += 1


if __name__ == "__main__":
    main()
