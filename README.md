## Summary
This script evalues the httpd access logs for Rucio WebUI deployments
and analysis the frequency of hitting the different endpoints.

## Usage

*NOTE: requires Python3*

python3 rucio_access_log_parser.py [-h] -f HTTPD_ACCESS_LOG_FILE [-o OUTPUT_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -f HTTPD_ACCESS_LOG_FILE
                        The path to httpd access logs to parse
  -o OUTPUT_FILE        The output file

## Author
Mayank Sharma <mayank.sharma@cern.ch>


## Version 
1.0
"""