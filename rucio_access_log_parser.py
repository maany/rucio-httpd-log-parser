import argparse
from functools import partial, reduce
import logging
import re


logger = logging.getLogger(__name__)

REGEX = r"(?P<ip>.*?) - - \[(?P<timestamp>.*?)\] \"(?P<verb>.*?) (?P<url>.*) .*\" (?P<status_code>\d*) .*"
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


def process_logs(logfile):
    processed_logs = []
    urls = {f"{url}": (0, []) for url, controller, description in COMMON_URLS}

    def match_and_count(match):
        url = match.group(4)
        for key in urls.keys():
            if url.startswith(key):
                count, entries = urls[key]
                entries.append(match.group(4))
                urls[key] = (count + 1, entries)
                return True
                
        return False

    processed_logs = [
        re.search(REGEX, line).groups()
        for line in logfile
        if re.match(REGEX, line) and match_and_count(re.match(REGEX, line))
    ]

    return processed_logs


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
    args = parser.parse_args()
    httpd_logfile = args.httpd_access_log_file
    try:
        process_logs(httpd_logfile)
    finally:
        args.httpd_access_log_file.close()
