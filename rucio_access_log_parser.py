"""[summary]
This script processes the httpd access logs for Rucio WebUI deployments
and generates the frequency of accessing the different endpoints.

[usage]

NOTE: requires Python3

python3 rucio_access_log_parser.py [-h] -f HTTPD_ACCESS_LOG_FILE [-o OUTPUT_FILE] [-p]

Rucio Access Log Parser

optional arguments:
  -h, --help            show this help message and exit
  -f HTTPD_ACCESS_LOG_FILE
                        The path to httpd access logs to parse
  -o OUTPUT_FILE        The output file
  -p                    Indicate logs from puppet managed nodes. (Only for Atlas)

[author]
Mayank Sharma <mayank.sharma@cern.ch>


[version] 
2.1
"""

import argparse
import logging
import re
import json

logger = logging.getLogger(__name__)
VERSION = 2.1
REGEX_PUPPET = r"(?P<ip>.*?) - - \[(?P<timestamp>.*?)\] \"(?P<verb>.*?) (?P<url>.*) .*\" (?P<status_code>\d*) .*"
REGEX_K8S = r"\[(?P<timestamp>.*?)\].*\"(?P<verb>.*?) (?P<url>.*) .*\".*\".*?\""
COMMON_URLS = (
    ("/account_rse_usage", "account_rse_usage", "Account RSE Usage"),
    ("/account", "account", "Account"),
    ("/bad_replicas", "bad_replicas", "Bad Replicas"),
    ("/bad_replicas/summary", "bad_replicas_summary", "Bad Replica Summary"),
    ("/did", "did", "Data Identifier"),
    ("/heartbeats", "heartbeats", "Heartbeats"),
    ("/lifetime_exception", "lifetime_exception", "Lifetime Exception"),
    ("/list_lifetime_exceptions", "list_lifetime_exceptions", "Lifetime Exception"),
    ("/list_accounts", "accounts", "Accounts"),
    ("/r2d2/approve", "approve_rules", "Rules in Approval State"),
    ("/r2d2/request", "request_rule", "Rucio Rule Definition Droid - Request Rule"),
    ("/r2d2/manage_quota", "rse_account_usage", "Manage Quota"),
    ("/r2d2", "list_rules", "Rucio Rule Definition Droid - List Rules"),
    ("/rse/protocol/add", "rse_add_protocol", "RSE Protocol"),
    ("/rses/add", "add_rse", "Add RSE"),
    ("/rse_usage", "rse_usage", "RSE Usage"),
    ("/rse_locks", "rse_locks", "RSE Locks"),
    ("/rses", "rses", "RSEs"),
    ("/rse", "rse", "RSE Info"),
    ("/rules", "rules", "Rules"),
    ("/rule", "rule", "Rule"),
    ("/search", "search", "Search"),
    ("/subscriptions/rules", "subscriptionrules", "Rules for Subscription"),
    ("/subscriptions_editor", "subscriptions_editor", "Subscriptions editor"),
    ("/subscriptions", "subscriptions", "Subscriptions"),
    ("/subscription", "subscription", "Subscription"),
    ("/suspicious_replicas", "suspicious_replicas", "Suspicious Replicas"),
)


def process_logs(logfile, puppet):
    regex, url_group_id = (REGEX_PUPPET, 4) if puppet else (REGEX_K8S, 3)

    urls = {f"{url}": (0, []) for url, controller, description in COMMON_URLS}
    total_log_entries = 0
    validated_log_entries = 0
    matched_log_entries = 0
    proxied_entries = []

    def _match_and_count(match):
        url = match.group(url_group_id)
        for key in urls.keys():
            if url.startswith(key):
                count, entries = urls[key]
                entries.append(match.group(url_group_id))
                urls[key] = (count + 1, entries)
                return True

        return False

    validate = lambda log: re.match(regex, log)

    for line in logfile.readlines():
        total_log_entries = total_log_entries + 1
        validated_log = validate(line)
        if not validated_log:
            continue
        if _match_and_count(validated_log):
            matched_log_entries = matched_log_entries + 1
        else:
            proxied_entries.append(line)
        validated_log_entries = validated_log_entries + 1

    urls = sorted(urls.items(), key=lambda d: d[1][0], reverse=True)
    output = {
        "version": VERSION,
        "total": total_log_entries,
        "validated": validated_log_entries,
        "matched": matched_log_entries,
        "unmatched": len(proxied_entries),
        "url_analysis": urls,
        # "proxied_entries": proxied_entries,
    }
    return json.dumps(output, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rucio Access Log Parser")
    parser.add_argument(
        "-f",
        dest="httpd_access_log_file",
        required=True,
        default="/var/log/httpd/access_log",
        type=argparse.FileType("r", encoding="UTF-8"),
        help="The path to httpd access logs to parse",
    )
    parser.add_argument(
        "-o",
        dest="output_file",
        default="./rucio_access_log_parser.output",
        type=argparse.FileType("w", encoding="UTF-8"),
        help="The output file",
    )
    parser.add_argument(
        "-p",
        dest="puppet",
        action="store_true",
        help="Indicate logs from puppet managed nodes. (Only for Atlas)",
    )
    args = parser.parse_args()
    httpd_logfile = args.httpd_access_log_file
    output_file = args.output_file
    puppet = args.puppet
    try:
        output = process_logs(httpd_logfile, puppet)
        output_file.write(output)
    finally:
        httpd_logfile.close()
        output_file.close()
