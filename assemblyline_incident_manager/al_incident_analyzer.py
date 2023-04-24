#!/usr/bin/env python3
"""
This file contains the code that does the "pulling". It requests all of the files that the user
has submitted to Assemblyline for analysis via the "pusher".

There are 4 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import logging
from time import sleep, time
import os

from assemblyline_incident_manager.helper import (
    init_logging,
    print_and_log,
    parse_args,
    prepare_query_value,
    get_al_client,
)

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "al_incident_analyzer_log.csv"
REPORT_FILE = "report.csv"


log = init_logging(LOG_FILE)


def main(args=None, arg_dict=None):
    """
    Example 1:
    al-incident-analyzer --url="https://<domain-of-Assemblyline-instance>" --user="<user-name>" --apikey="/path/to/file/containing/apikey" --incident_num=123

    Example 2:
    al-incident-analyzer --config ~/al_config.toml --incident_num=123 --min_score=100
    """

    if arg_dict is None:
        arg_dict = parse_args(args, al_incident="Analyzer")
    auth = arg_dict.get("auth", {})
    server = arg_dict.get("server", {})
    incident = arg_dict.get("incident", {})

    incident_num = prepare_query_value(incident.get("incident_num"))

    min_score = incident.get("min_score", 0)

    # Here is the query that we will be using to retrieve all submission details
    query = f'metadata.incident_number:"{incident_num}" AND min_score:>={min_score}'
    print_and_log(log, f"INFO,Query: {query}", logging.DEBUG)

    if arg_dict.get("is_test"):
        print_and_log(
            log, f"INFO,The query that you will make is: {query}", logging.DEBUG
        )
        return

    # Overwrite the report file?
    if os.path.exists(REPORT_FILE) and not _handle_overwrite():
        return

    al_client = get_al_client(server, auth, log)
    if not al_client:
        return

    report_file = open(REPORT_FILE, "a")
    report_file.write("FilePath,SHA256,Score,URL,Errors\n")

    start_time = time()
    number_of_files_with_results = 0

    # Create a generator that yields the SIDs for our query
    submission_res = al_client.search.stream.submission(query, fl="sid")
    for submission in submission_res:
        sid = submission["sid"]

        # Wait until the submission has completed
        while not al_client.submission.is_completed(sid):
            print_and_log(
                log,
                f"INFO,{sid} is not completed yet. Sleeping for 5 seconds and trying again.",
                logging.DEBUG,
            )
            sleep(5)

        # Deep dive into the submission to get the files
        submission_details = al_client.submission(sid)

        for file in submission_details["files"]:
            file_name = _prepare_file_name(submission_details["metadata"]["filename"])
            msg = f"{file_name},{file['sha256']},{submission_details['max_score']},{server}/submission/report/{sid},{submission_details['errors']}\n"
            print_and_log(log, msg, logging.DEBUG)
            report_file.write(msg)
            number_of_files_with_results += 1

    msg = (
        f"INFO,Results Query Complete\n"
        f"Number of files with results = {number_of_files_with_results}\n"
        f"Total time elapsed: {time() - start_time}s"
    )
    print_and_log(log, msg, logging.DEBUG)


def _handle_overwrite() -> bool:
    overwrite = input(
        f"A {REPORT_FILE} already exists. Do you wish to overwrite? [y/n]:"
    )
    if overwrite == "y":
        os.remove(REPORT_FILE)
        return True
    elif overwrite == "n":
        print_and_log(
            log,
            f"INFO,A {REPORT_FILE} already exists. You chose not to overwrite the file and to exit.",
            logging.DEBUG,
        )
        return False
    else:
        print_and_log(
            log,
            "INFO,You submitted a value that was neither [y/n]. Exiting.",
            logging.DEBUG,
        )
        return False


def _prepare_file_name(file_name: str) -> str:
    if "," in file_name:
        file_name = file_name.replace(",", "")
    return file_name


if __name__ == "__main__":
    main()
