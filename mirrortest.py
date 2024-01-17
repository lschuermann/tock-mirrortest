#!/usr/bin/env python3

import sys
import json
import requests
import time
import hashlib
import logging
import collections
import argparse
import jinja2
import tempfile
import copy
import difflib

# Fetch the full file and compare its checksum every 7 days.
FULL_FETCH_INTERVAL = 7 * 60 * 60 * 24

# Inspired by https://stackoverflow.com/a/14014877
class TransparentHasher:
    def __init__(self, hasher, source):
        self._hasher = hasher
        self._source = source

    def __iter__(self):
        for chunk in self._source:
            self._hasher.update(chunk)
            yield chunk

    def hasher(self):
        return self._hasher

def mirrortest(log, mirrors, urls):
    issues = []

    # Test each URL that has not been marked "ignored", and where the mirror is
    # not marked "dead":
    for url, record in urls.items():
        if record["ignored"] == True:
            log.debug(f"URL \"{url}\" is marked as ignored, skipping...")
            continue
        elif mirrors[record["mirror"]]["dead"] == True:
            log.debug(f"URL \"{url}\"'s mirror is marked as dead, skipping...")
            continue

        # A shortcut function to "template" an issue dictionary and insert it
        # into the issues list:
        def report_issue(t, **kwargs):
            nonlocal issues
            issues += [{
                "type": t,
                "url": url,
                "mirror" : {
                    "base_url": record["mirror"],
                    "admins": mirrors[record["mirror"]]["admins"],
                },
                **kwargs
            }]

        # Every once in a while, we want to fetch the full file to detect things
        # such as silent data corruption. We further do this when the file's
        # checksum it set to None.
        full_fetch = record["checksum"] is None or record["last_fetch"] is None \
            or record["last_fetch"] + FULL_FETCH_INTERVAL < int(time.time())

        method = "GET" if full_fetch else "HEAD"
        log.info(f"Testing URL \"{url}\" ({method})...")

        try:
            if full_fetch:
                resp = requests.get(
                    url, timeout=30, allow_redirects=True, stream=True)
            else:
                resp = requests.head(url, timeout=30, allow_redirects=True)

            # Print the full series of redirects:
            for step in (resp.history if resp.history else []):
                log.info(f"  Followed redirect from \"{step.url}\" ({step.status_code})")
            if resp.history:
                log.info(f"  Final URL: \"{resp.url}\": SUCCESS ({resp.status_code})")

        except e:
            log.warning(f" FAIL: {request_exception}")
            report_issue("request_error", error_message=str(request_exception))
            continue

        # Validate the received response's Content-Length header:
        resp_content_length = list(filter(
            lambda header: header[0].lower() == "content-length",
            resp.headers.items()))

        if len(resp_content_length) > 0 and \
           int(resp_content_length[0][1]) != record["size"]:
            log.warning(
                f"Diverging content-length header: {resp_content_length[0][1]} "
                + f"bytes fetched now vs. {record['size']} bytes on record"
            )
            report_issue(
                "content_length_header_record_mismatch",
                content_length_header=int(resp_content_length[0][1]),
                record_size=record["size"],
            )
            continue

        if not full_fetch:
            # Everything's okay, update the last_head timestamp:
            record["last_head"] = int(time.time())
        else:
            # We're streaming the response, read it into the SHA-256 hasher and
            # validate that the content_length header matches the true file
            # size:
            hash_filter = TransparentHasher(
                hashlib.sha256(),
                resp.iter_content(chunk_size=16 * 1024))

            # This will stream all data and collect the number of bytes:
            bytes_recvd = sum(map(lambda chunk: len(chunk), hash_filter))

            if int(resp_content_length[0][1]) != bytes_recvd:
                log.warning(
                    f"Received {bytes_recvd} bytes, but Content-Length header "
                    + f"specified {resp_content_length[0][1]} bytes (size on "
                    + f"record: {record['size']} bytes)"
                )
                report_issue(
                    "content_length_header_response_mismatch",
                    content_length_header=int(resp_content_length[0][1]),
                    response_size=bytes_recvd,
                )
                continue

            if record["size"] is not None and record["size"] != bytes_recvd:
                raise Exception(
                    f"Received {bytes_recvd}, but size on record is {record['size']}"
                )
            else:
                # This is the initial fetch, update the size:
                record["size"] = bytes_recvd

            fetch_csum = hash_filter.hasher().digest()
            if record["checksum"] is not None:
                record_csum = bytes.fromhex(record["checksum"])
                if record_csum != fetch_csum:
                    logging.warning(
                        "Received file has diverging checksum ("
                        + f"fetched: {fetch_csum.hex()} vs. on record: "
                        + f"{record_csum.hex()})"
                    )
                    report_issue(
                        "checksum_mismatch",
                        response_checksum=fetch_csum.hex(),
                        record_checksum=record_csum.hex(),
                    )
            else:
                # This is the initial fetch, store the checksum:
                record["checksum"] = fetch_csum.hex()

            # Everything's okay, update the last_fetch timestamp:
            record["last_fetch"] = int(time.time())

        # After the above, we should always have a non-null value for all of
        # last_fetch, size, and checksum:
        assert record["last_fetch"] is not None
        assert record["size"] is not None
        assert record["checksum"] is not None

    return issues

def main():
    parser = argparse.ArgumentParser(
        prog = "mirrortest")

    # Global options:
    parser.add_argument("-v", "--verbose", action="store_true")

    # Subcommands:
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # test-mirrors subcommand:
    test_mirrors_parser = subparsers.add_parser("test-mirrors")
    test_mirrors_parser.add_argument(
        "-n", "--dry-run", action="store_true",
        help="Dry run, don't update any state")
    test_mirrors_parser.add_argument(
        "--diff", action="store_true",
        help="Print diff of changes to state")
    test_mirrors_parser.add_argument(
        "-u", "--urls-json", required=True,
        help="URLs database file")
    test_mirrors_parser.add_argument(
        "-m", "--mirrors-json", required=True,
        help="Mirrors database file")
    test_mirrors_parser.add_argument(
        "--gh-issue-template",
        help="Path to GitHub issue template (Jinja2)")
    test_mirrors_parser.add_argument(
        "--gh-issue-out",
        help="GitHub issue file to generate from template in case of errors")

    args = parser.parse_args()

    # Initialize the logging facility:
    ch = logging.StreamHandler()
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(fmt)
    log = logging.getLogger('mirrortest')
    log.addHandler(ch)
    if args.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    if args.subcommand == "test-mirrors":
        # Argument sanity checks:
        if args.gh_issue_out and not args.gh_issue_template:
            log.error("Cannot generate GitHub issue without template.")
            sys.exit(1)

        with open(args.gh_issue_template, "r") as f:
            gh_issue_template = jinja2.Template(f.read())

        with open(args.urls_json, "r") as f:
            urls = json.load(f)

        with open(args.mirrors_json, "r") as f:
            mirrors = json.load(f)

        updated_urls = copy.deepcopy(urls)
        issues = mirrortest(log, mirrors, updated_urls)

        if args.diff:
            diffstr = lambda s: list(map(lambda l: l + "\n", s.split("\n")))
            original_str = diffstr(
                json.dumps(urls, indent=2, sort_keys=True))
            updated_str = diffstr(
                json.dumps(updated_urls, indent=2, sort_keys=True))
            sys.stdout.writelines(difflib.unified_diff(
                original_str,
                updated_str,
                fromfile='urls.json',
                tofile='updated.json',
            ))

        if not args.dry_run:
            # Write the results back to the urls.json file:
            with open(args.urls_json, "w") as f:
                json.dump(updated_urls, f, indent=2, sort_keys=True)

        if args.gh_issue_out and len(issues) != 0:
            with open(args.gh_issue_out, "w") as f:
                f.write(gh_issue_template.render(issues=issues))

        if len(issues) != 0:
            return 1

if __name__ == "__main__":
    sys.exit(main())
