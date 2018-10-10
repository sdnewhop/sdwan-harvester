#!/usr/bin/env python3

import argparse
import os
import sys

import harvester.core as core

# Default input file with queries
core.QUERIES_JSON_FILE = "shodan_queries.json"

# Default confidence level
core.DEFAULT_CONFIDENCE = "certain"

# Default quantity of results
core.MAX_COUNTRIES = 10
core.MAX_VENDORS = 10
core.MAX_VULNERS = 10

# Default paths and directories
core.NMAP_SCRIPTS_PATH = "nse-scripts"
core.PY_SCRIPTS_PATH = "py-scripts"
core.RESULTS_DIR = "results"


def get_key_from_env():
    """
    Get Shodan API Key from environment variable

    :return: Shodan API key from env variable (str)
    """
    try:
        shodan_api_key = os.environ['SHODAN_API_KEY']
        return shodan_api_key
    except KeyError:
        print(
            'Please set the environment variable SHODAN_API_KEY or use -sk key')
        sys.exit(1)


def main():
    """
    Main interface for harvester core

    :return: None
    """
    if sys.version_info < (3, 6):
        print('Required python version is 3.6 or greater')
        sys.exit(1)

    if len(sys.argv) == 1:
        print(
            "Usage: '{script_name} -h' for help".format(
                script_name=sys.argv[0]))
        sys.exit(1)

    parser = argparse.ArgumentParser(description=".")
    parser.add_argument("-sk", "--shodan-key", action="store",
                        default=None, help="Shodan API key")
    parser.add_argument("-n", "--new", action="store_true",
                        help="New scan in shodan")
    parser.add_argument("-q", "--queries", action="store",
                        default=core.QUERIES_JSON_FILE,
                        help="File with queries")
    parser.add_argument("-d", "--destination", action="store",
                        default=core.RESULTS_DIR, help="Destination directory")
    parser.add_argument("-c", "--confidence", default=core.DEFAULT_CONFIDENCE,
                        action="store", help="""Confidence level. Available
                                                levels: certain, firm,
                                                tentative""")
    parser.add_argument("-v", "--vulners", action="store", nargs='*',
                        help="""List of vendors for vulners scan, e.g., 
                                '--vulners silver peak, arista, talari'.  
                                Use '--vulners all' to include all vendors 
                                in statistics.""")
    parser.add_argument("-mv", "--max-vendors", default=core.MAX_VENDORS, type=int,
                        action="store",
                        help="Max number of vendors in statistics")
    parser.add_argument("-mc", "--max-countries", default=core.MAX_COUNTRIES,
                        type=int,
                        action="store",
                        help="Max number of countries in statistics")
    parser.add_argument("-maxv", "--max-vulners", default=core.MAX_VULNERS,
                        type=int, action="store",
                        help="Max number of vulners in statistics")
    args = parser.parse_args()

    # Try to get key from environment if it was not passed with CLI
    if not args.shodan_key and args.new is True:
        args.shodan_key = get_key_from_env()

    # Check confidence level
    if args.confidence.lower() not in ['certain', 'firm', 'tentative']:
        print('Wrong confidence level. Use -h key for help.')
        sys.exit(1)

    # Run harvester
    core.run(args)


if __name__ == '__main__':
    main()
