## Summary
This script processes the httpd access logs for Rucio WebUI deployments
and generates the frequency of accessing the different endpoints.

## Usage

*NOTE: requires Python3*
```
python3 rucio_access_log_parser.py [-h] -f HTTPD_ACCESS_LOG_FILE [-o OUTPUT_FILE] [-p]

Rucio Access Log Parser

optional arguments:
  -h, --help            show this help message and exit
  -f HTTPD_ACCESS_LOG_FILE
                        The path to httpd access logs to parse
  -o OUTPUT_FILE        The output file
  -p                    Indicate logs from puppet managed nodes. (Only for Atlas)

```
## Author
Mayank Sharma <mayank.sharma@cern.ch>


## Version 
2.0
