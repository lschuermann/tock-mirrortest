#!/usr/bin/env python3

import json
import requests
import time

# TODO: collect URLs from the upstream repositories, and add them to urls.json
# automatically.

with open("./urls.json", "r") as f:
    urls = json.load(f)

with open("./mirrors.json", "r") as f:
    mirrors = json.load(f)

# Now, test each URL that has not been marked "ignored", and where the mirror is
# not marked "dead":
for url, record in urls.items():
    if record["ignored"] == True or mirrors[record["mirror"]]["dead"] == True:
        continue

    print(f"Testing URL \"{url}\"...", flush=True, end="")
    try:
        resp = requests.head(url, timeout=30, allow_redirects=True)
        print(f" SUCCESS ({resp.status_code})")
        for step in (resp.history if resp.history else []):
            print(f"  Followed redirect from \"{step.url}\" ({step.status_code})")
        if resp.history:
            print(f"  Final URL: \"{resp.url}\"")
    except e:
        print(" FAIL")
        # TODO: create GitHub issue instead
        raise Exception(f"Mirror down: {url} {request_exception}")

    # Validate the received response:
    resp_content_length = list(filter(lambda header: header[0].lower() == "content-length", resp.headers.items()))
    if len(resp_content_length) > 0 and int(resp_content_length[0][1]) != record["size"]:
        # TODO: create GitHub issue instead
        raise Exception("Diverging content-length: {} fetched now vs. {} on file".format(
            resp_content_length[0][1],
            record["size"]
        ))

    # Everything's okay, update the last_head timestamp:
    record["last_head"] = int(time.time())

# Write the results back to the urls.json file:
with open("urls.json", "w") as f:
    json.dump(urls, f, indent=2)
