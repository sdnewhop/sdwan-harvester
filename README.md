# SD-WAN Harvester
:globe_with_meridians: SD-WAN Internet Census Framework

## Disclaimer
This project is no longer maintained. It is stable and you still can use it for SD-WAN scanning, but currently, more preferable and accurate way to scan different things on the internet (not only SD-WAN solutions) is to use our new Grinder Framework.  
  
**[:mag_right: Grinder Framework](https://github.com/sdnewhop/grinder)**  

## Contents
1. [Description](#description)
1. [Slides](#slides)
1. [Requirements](#requirements)
1. [Installation](#installation)
1. [Usage](#usage)
   - [Command Line Arguments](#command-line-arguments)
   - [Examples](#examples)

## Description
`SD-WAN Harvester` tool was created to automatically enumerate and fingerprint SD-WAN nodes on the Internet. 
It uses Shodan search engine for discovering, NMAP NSE scripts for fingerprinting, and masscan to implement some specific checks.

## Slides
- [SD-WAN Internet Census. Zero Nights 2018](https://github.com/sdnewhop/sdwannewhope/blob/master/slides/zn-2018.pdf)

## Requirements
`SD-WAN Harvester` requires [Python 3.6](https://www.python.org/getit/) or later and [Nmap](https://nmap.org/download.html).

You also need an Shodan API key.

## Installation
1. Clone the repository:
```
git clone https://github.com/sdnewhop/sdwan-harvester.git
```
2. Install `pip` requirements:
```
python3.6 -m pip install -r requirements.txt
```
3. Run the script:
```
python3.6 harvester.py -h
```
4. Set your Shodan key via a command line argument
```
./harvester.py -sk YOUR_SHODAN_KEY
```
or via an environment variable
```
export SHODAN_API_KEY=YOUR_API_KEY_HERE
./harvester.py (without -sk key)
```

## Usage
### Command Line Arguments
1. `-h, --help` - show the help message and exit.  

2. `-sk SHODAN_KEY, --shodan-key SHODAN_KEY` - set a Shodan API key.

3. `-n, --new` - initiate a new discovery using Shodan.  

4. `-q QUERIES, --queries QUERIES` - specify the file containing SD-WAN queries and filters for Shodan.
*Default value is `shodan_queries.json`.*

5. `-d DESTINATION, --destination DESTINATION` - the directory where results will be stored.
*Default value is `results`.*

6. `-C CONFIDENCE, --confidence CONFIDENCE` - set the confidence level (`certain`, `firm`, or `tentative`).  
*Default value is `certain`.*

7. `-v [VULNERS [VULNERS ...]], --vulners [VULNERS [VULNERS ...]]` - the list of venodrs checked by Shodan vulnerability scanner. For example, `--- vulners silver peak, arista, talari` command starts finding of known vulnerabilities for `silver peak`, `arista` and `talari` products. Use `--vulners all` to run scanning for all vendors.
*By default, Shodan vulnerability scanning is turned off.*

8. `-mv MAX_VENDORS, --max-vendors MAX_VENDORS` - the Maximum Number of Vendors shown in reports.  
*Default value is `10`.*

9. `-mc MAX_COUNTRIES, --max-countries MAX_COUNTRIES` - the Maximum Number of Countries shown in reports.
*Default value is `10`.*

10. `-maxv MAX_VULNERS, --max-vulners MAX_VULNERS` - the Maximum Number of Vulnerabilities shown in reports.  
*Default value is `10`.*

11. `-u, --update-markers` - Update map markers.

### Examples
Show help 
```
python3.6 harvester.py -h
```
Run an enumeration
```
python3.6 harvester.py -sk YOUR_API_KEY -n
```
Run an enumeration with `firm` level of confidence
```
python3.6 harvester.py -sk YOUR_API_KEY -n -c firm
```
Run a vulnerability scan against `talari` vendor
```
python3.6 harvester.py -sk YOUR_API_KEY -n -v talari
```
Run a new vulnerability scan for all vendors. The Maximum Number of Vendors is 8, the Maximum Number of Countries is 8, and the Maximum Number of CVEs is 8
```
python3.6 harvester.py -sk YOUR_API_KEY -n -v all -mv 8 -mc 8 -maxv 8
```
Run a new scan with all features enabled
```
python3.6 harvester.py -sk YOUR_API_KEY -n -v all -c all
```
Process data from previous scan results (for example, if you want to build new charts and graphics containing fewer vendors, countries, or vulners.)
```
python3.6 harvester.py -v -mv <num> -mc <num> -maxv <num>
```
