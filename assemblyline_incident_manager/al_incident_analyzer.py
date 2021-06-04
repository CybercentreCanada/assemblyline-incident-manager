"""
This file contains the code that does the "pulling". It requests all of the files that the user
has submitted to Assemblyline for analysis via the "pusher".

There are 4 phases in the script, each documented accordingly.
"""

# The imports to make this thing work. All packages are default Python libraries except for the
# assemblyline_client library.
import logging
import click
from time import sleep, time
import os

from assemblyline_client import get_client
from assemblyline_incident_manager.helper import init_logging, print_and_log, _validate_url, prepare_apikey, prepare_query_value

# These are the names of the files which we will use for writing and reading information to
LOG_FILE = "al_incident_analyzer_log.csv"
REPORT_FILE = "report.csv"


log = init_logging(LOG_FILE)


# These are click commands and options which allow the easy handling of command line arguments and flags
@click.group(invoke_without_command=True)
@click.option("--url", required=True, type=click.STRING, help="The target URL that hosts Assemblyline.")
@click.option("-u", "--username", required=True, type=click.STRING, help="Your Assemblyline account username.")
@click.option("--apikey", required=True, type=click.Path(exists=True, readable=True),
              help="A path to a file that contains only your Assemblyline account API key. NOTE that this API key requires write access.")
@click.option("--min_score", default=0, type=click.INT, help="The minimum score for files that we want to query from Assemblyline.")
@click.option("--incident_num", required=True, type=click.STRING, help="The incident number that each file is associated with.")
@click.option("-t", "--is_test", is_flag=True, help="A flag that indicates that you're running a test.")
def main(url: str, username: str, apikey: str, min_score: int, incident_num: str, is_test: bool):
    """
    Example:
    al-incident-analyzer --url="https://<domain-of-Assemblyline-instance>" --username="<user-name>" --apikey="/path/to/file/containing/apikey" --incident_num=123
    """
    # Here is the query that we will be using to retrieve all submission details
    incident_num = prepare_query_value(incident_num)
    query = f"metadata.incident_number:\"{incident_num}\" AND max_score:>={min_score}"
    print_and_log(log, f"INFO,Query: {query}", logging.DEBUG)

    if is_test:
        print_and_log(log, f"INFO,The query that you will make is: {query}", logging.DEBUG)
        return

    # Overwrite the report file?
    if os.path.exists(REPORT_FILE) and not _handle_overwrite():
        return

    # Parameter validation
    if not _validate_url(log, url):
        return

    # No trailing forward slashes in the URL!
    url = url.rstrip("/")

    apikey_val = prepare_apikey(apikey)

    # Create the Assemblyline Client
    al_client = get_client(url, apikey=(username, apikey_val))

    report_file = open(REPORT_FILE, "a")
    report_file.write("FilePath,SHA256,Score,URL,Errors\n")

    start_time = time()
    number_of_files_with_results = 0

    # Create a generator that yields the SIDs for our query
    submission_res = al_client.search.stream.submission(query, fl='sid')
    for submission in submission_res:
        sid = submission["sid"]

        # Wait until the submission has completed
        while not al_client.submission.is_completed(sid):
            print_and_log(log, f"INFO,{sid} is not completed yet. Sleeping for 5 seconds and trying again.", logging.DEBUG)
            sleep(5)

        # Deep dive into the submission to get the files
        submission_details = al_client.submission(sid)

        for file in submission_details["files"]:
            file_name = _prepare_file_name(submission_details['metadata']['filename'])
            msg = f"{file_name},{file['sha256']},{submission_details['max_score']},{url}/submission/report/{sid},{submission_details['errors']}\n"
            print_and_log(log, msg, logging.DEBUG)
            report_file.write(msg)
            number_of_files_with_results += 1

    msg = f"INFO,Results Query Complete\n" \
          f"Number of files with results = {number_of_files_with_results}\n" \
          f"Total time elapsed: {time() - start_time}s"
    print_and_log(log, msg, logging.DEBUG)


def _handle_overwrite() -> bool:
    overwrite = input(f"A {REPORT_FILE} already exists. Do you wish to overwrite? [y/n]:")
    if overwrite == "y":
        os.remove(REPORT_FILE)
        return True
    elif overwrite == "n":
        print_and_log(log, f"INFO,A {REPORT_FILE} already exists. You chose not to overwrite the file and to exit.",
                      logging.DEBUG)
        return False
    else:
        print_and_log(log, "INFO,You submitted a value that was neither [y/n]. Exiting.", logging.DEBUG)
        return False


def _prepare_file_name(file_name: str) -> str:
    if "," in file_name:
        file_name = file_name.replace(",", "")
    return file_name


if __name__ == "__main__":
    main()
