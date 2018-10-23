#!/usr/bin/env python3

import copy
import csv
import json
import os
import re
import sys
import time
from collections import Counter
from importlib import import_module

import nmap
import shodan
from colorama import Fore, Style
from matplotlib import pyplot as plt
from pycountry_convert import \
    country_alpha2_to_continent_code as code_to_continent
from pycountry_convert import \
    country_name_to_country_alpha2 as country_to_code

# Interface part
# Can be overwritten by calling module
QUERIES_JSON_FILE = "shodan_queries.json"
RESULTS_DIR = "results"
DEFAULT_CONFIDENCE = "certain"
MAX_COUNTRIES = 10
MAX_VENDORS = 10
MAX_VULNERS = 10

# Additional scripts
NMAP_SCRIPTS_PATH = "../nse-scripts"
PY_SCRIPTS_PATH = "../py-scripts"

# Map markers
MAP_MARKERS_DIR = "../samples/map"

# Sort output files by extensions
JSON_DIR = "json"
CSV_DIR = "csv"
TXT_DIR = "txt"
PNG_DIR = "png"

# Output json dict dumps
RESULT_JSON_FILE = "Result.json"
COUNTRIES_JSON_FILE = "Countries.json"
CONTINENTS_JSON_FILE = "Continents.json"
VULNERS_JSON_FILE = "Vulnerabilities.json"
VULNERS_BY_VENDORS_JSON = "Vulnerabilities_by_vendors.json"
PRODUCTS_JSON_FILE = "Products.json"

# Output csv files
RESULT_CSV_FILE = "Result.csv"
GROUPED_BY_VERSION_FILE = "Grouped_by_version.csv"

# Output txt tops
RESULT_TOP_TXT_FILE = "Result_top.txt"
COUNTRIES_TOP_TXT_FILE = "Countries_top.txt"
CONTINENTS_TOP_TXT_FILE = "Continents_top.txt"
VULNERS_TOP_TXT_FILE = "Vulnerabilities_top.txt"
PRODUCTS_TOP_TXT_FILE = "Products_top.txt"

# Output piechart pictures
RESULT_PIECHART_FILE = "Vendors.png"
COUNTRIES_PIECHART_FILE = "Countries.png"
CONTINENTS_PIECHART_FILE = "Continents.png"
VULNERS_PIECHART_FILE = "Vulnerabilities.png"
PRODUCTS_PIECHART_FILE = "Products.png"

# Matplot chart ids
VENDOR_PIE_CHART_ID = 0
COUNTRIES_PIE_CHART_ID = 1
CONTINENTS_PIE_CHART_ID = 2
VULNERS_PIE_CHART_ID = 3
PRODUCTS_PIE_CHART_ID = 4
VULNERS_BY_VENDORS_PIE_CHART_ID = 5

# Pie chart properties
PIE_DEFAULT_AUTOPCT = "%1.1f%%"
PIE_LABEL_FONT_SIZE = 6
PIE_SUPTITLE_FONT_SIZE = 12
PIE_DPI = 200

# Pie chart names
BASIC_TITLE = "Percentage of SD-WAN Nodes by"
PIE_VENDORS_TITLE = "{base} Vendors".format(base=BASIC_TITLE)
PIE_PRODUCTS_TITLE = "{base} Products".format(base=BASIC_TITLE)
PIE_COUNTRIES_TITLE = "{base} Countries".format(base=BASIC_TITLE)
PIE_CONTINENTS_TITLE = "{base} Continents".format(base=BASIC_TITLE)
PIE_VULNERABILITIES_TITLE = "{base} Vulnerabilities".format(base=BASIC_TITLE)
PIE_VULNERS_BY_VENDORS_TITLE_ADD = "most common vulnerabilities"

# Sleep time in case of errors and basic request delay (1 req/sec)
REQUEST_LIMIT_SLEEP_TIME = 5
REQUEST_DELAY_SLEEP_TIME = 1

# Terminal statuses color
ADD_VULNERABILITIES_COLOR = Fore.CYAN
ADD_SNMP_COLOR = Fore.LIGHTCYAN_EX
PASS_VENDOR_BY_CONFIDENCE_COLOR = Fore.LIGHTBLUE_EX
PRODUCT_FOUND_COLOR = Fore.LIGHTCYAN_EX
ERROR_COLOR = Fore.LIGHTRED_EX
RESET_COLOR = Style.RESET_ALL


def write_result_to_file_json(result_array, dest_dir, filename):
    """
    Write result array to output json file

    :param result_array: result array (list)
    :param dest_dir: destination directory (str)
    :param filename: name of json file to save (str)
    :return: None
    """
    if not result_array or result_array is None:
        return

    try:
        with open(
                "{dest}/{json}/{result_file}".format(
                    dest=dest_dir,
                    json=JSON_DIR,
                    result_file=filename),
                mode="w") as file:
            file.write(json.dumps(result_array))
    except FileNotFoundError:
        print("{color}Error: destination file write failed{reset}".format(
            color=ERROR_COLOR, reset=RESET_COLOR))


def write_result_to_file_csv(result_array, dest_dir,
                             filename=RESULT_CSV_FILE):
    """
    Write result array to output csv file

    :param result_array: result array of dicts (dict)
    :param dest_dir: destination directory (str)
    :param filename: name of .csv file (str)
    :return: None
    """
    if not result_array or result_array is None:
        return

    try:
        with open(
                "{dest}/{csv}/{result_file}".format(
                    dest=dest_dir,
                    csv=CSV_DIR,
                    result_file=filename),
                mode="w") as file:
            writer = csv.DictWriter(file, fieldnames=result_array[0].keys())
            writer.writeheader()
            for row in result_array:
                writer.writerow(row)
    except FileNotFoundError:
        print("{color}Error: destination file write failed{reset}".format(
            color=ERROR_COLOR, reset=RESET_COLOR))


def group_by_version(result_dict):
    """
    Group results by version

    :param result_dict: dictionary with results (dict)
    :return: dictionary with results grouped by versions (dict)
    """
    result = {}

    for element in result_dict:
        version = element["additional_info"]
        key = "{version};{product}".format(version=version,
                                           product=element["product"])
        if key in result.keys():
            result[key]["ip_list"] += ",{ip}".format(ip=element["ip"])
        else:
            result[key] = {
                "vendor": element["vendor"],
                "product": element["product"],
                "ip_list": element["ip"]
            }
    return result


def add_to_array(result_list, result_csv_list, current_elem):
    """
    Add results to resulting array (unique hosts and unique pairs of
    ips and ports)

    :param result_list: result array of unique hosts (list)
    :param result_csv_list: result array of unique ips and ports (list)
    :param current_elem: current shodan search result (dict)
    :return: None
    """
    for res in result_list:
        if (current_elem["ip"], current_elem["port"]) == (
                res["ip"], res["port"]):
            break
    # If ip and port is never repeat in result list
    else:
        elem_copy = copy.deepcopy(current_elem)
        result_csv_list.append(elem_copy)
        result_list.append(elem_copy)


def nmap_script_exec(nm, ip, port, script):
    """
    Execute nmap script and get information

    :param nm: nmap port scanner object
    :param ip: ip of host (str)
    :param port: port of host (str)
    :param script: name of script (str)
    :return: appliance version (str)
    """
    res = nm.scan(ip, str(port),
                  arguments="-Pn --script={nmap_scripts}/{script_name}"
                  .format(nmap_scripts=NMAP_SCRIPTS_PATH, script_name=script))
    script_name = script.split(".")[0]
    raw_script = res["scan"][ip]["tcp"][port].get("script")

    if raw_script is None:
        return None
    raw_version = raw_script[script_name]
    version_index = raw_version.find("Version:")
    if version_index == -1:
        return None
    version = raw_version[version_index + len("Version: "):]
    return version


def python_script_exec(script, ip):
    """
    Import additional python script and run it

    :param script: script name from json (str)
    :return: version (str)
    """
    if script.endswith('.py'):
        py_module = script[:-3]
    else:
        py_module = script

    try:
        module = import_module('.' + py_module, package=PY_SCRIPTS_PATH)
    except Exception:
        return

    if not module:
        return
    version = module.main(ip)
    if not version:
        return
    return version


def get_info(nm, script, vendor, elem):
    """
    Check vendor and port before nmap script executing

    :param nm: nmap port scanner object
    :param script: name of script (str)
    :param vendor: current vendor (str)
    :param elem: dict for current elem search results (dict)
    :return: call to nmap_script_exec function
    """
    if vendor.lower() == "silver peak systems":
        data = elem.get("data")
        if data is not None and "VXOA " in data:
            return data.encode("utf-8", "ignore")

        tmp_http = elem.get("http")
        if tmp_http is not None:
            redirects = tmp_http.get("redirects")
            if not redirects:
                return None
            rdata = redirects[0].get("data")
            search_result = re.search(r"Location:\s*\/([0-9_.]+)\/", rdata)
            if search_result:
                return search_result.group(1)
        if str(elem.get("port")) in ["80", "443", "8080"] and script:
            return nmap_script_exec(nm, elem.get("ip_str"), elem.get("port"),
                                    script)

    elif vendor.lower() == "arista":
        data = elem.get("data")
        if data is not None and "EOS " in data:
            version_index = data.find("EOS version ")
            version_index_end = data.find(" running")
            if version_index == -1:
                return None
            version = data[version_index +
                           len("EOS version "):version_index_end]
            return version

    # Check if we got nmap or python script
    else:
        if str(elem.get("port")) in ["80", "443", "8080"]:
            if not script:
                return
            if script.endswith(".nse"):
                return nmap_script_exec(nm, elem.get("ip_str"),
                                        elem.get("port"), script)
            if script.endswith(".py"):
                return python_script_exec(script, elem.get("ip_str"))


def delete_build(dver):
    """
    Remove build from raw version

    :param dver: version (str)
    :return: version without build number (str)
    """
    if dver is None:
        return dver

    spl_ = dver.split("_")
    splr = dver.split("r")
    spld = dver.split(".")
    splm = dver.split("-")

    if dver[:2] == "r7":
        return dver[1] + "." + dver[3]
    if len(splm) > 2:
        return splm[-1].split("r")[0]
    if len(splr) == 2 and splr[0] and splr[1]:
        return splr[0]
    if len(spl_) == 2:
        return spl_[0]
    if len(spld) > 3 and len(spld[3]) > 4:
        return ".".join(spld[:-2])

    return dver


def make_autopct(values):
    """
    Make plot with percents and count (e.g 15% (20))

    :param values: values to count (list)
    :return: percent and count (func)
    """

    def percent_and_count(pct):
        total = sum(values)
        val = int(round(pct * total / 100.0))
        return '{p:1.1f}% ({v:d})'.format(p=pct, v=val)

    return percent_and_count


def create_top_and_chart(results, max_vendors, dest):
    """
    Create pyplot pie chart by vendors

    :param results: list of search results (list)
    :param max_vendors: max number of vendors in statistic (int)
    :param dest: destination directory (list)
    :return: None
    """
    GLOBAL_TOP = {}

    for result in results:
        key = result["vendor"]
        if GLOBAL_TOP.get(key) is None:
            GLOBAL_TOP[key] = 1
        else:
            GLOBAL_TOP[key] += 1

    top_max = ""
    max_vendors_list = sorted(
        GLOBAL_TOP.items(), key=lambda x: -x[1])[:max_vendors]
    for key, _ in max_vendors_list:
        top_max += "Vendor: {name} Found unique pairs (hosts + port): {unique}\n".format(
            name=key, unique=GLOBAL_TOP[key])

    try:
        with open(
                "{dest}/{txt}/{result_file}".format(dest=dest,
                                                    txt=TXT_DIR,
                                                    result_file=RESULT_TOP_TXT_FILE),
                mode="w") as file:
            file.write(top_max)
    except FileNotFoundError:
        print("{color}Error: destination file write failed{reset}".format(
            color=ERROR_COLOR, reset=RESET_COLOR))
        return

    global_values = [value for key, value in max_vendors_list]
    global_keys = [key for key, value in max_vendors_list]
    max_value = max(global_values)
    explode = [0 for x in range(len(global_keys))]
    explode[list(global_values).index(max_value)] = 0.1
    plt.figure(VENDOR_PIE_CHART_ID)
    plt.subplots_adjust(bottom=.05, left=.01, right=.99, top=.90, hspace=.35)
    plt.pie(global_values, explode=explode, labels=global_keys,
            autopct=make_autopct(global_values),
            textprops={'fontsize': PIE_LABEL_FONT_SIZE})
    plt.axis("equal")
    plt.suptitle(PIE_VENDORS_TITLE, fontsize=PIE_SUPTITLE_FONT_SIZE)

    plt.gcf().set_dpi(PIE_DPI)
    plt.savefig("{dest}/{png}/{result_file}".format(dest=dest,
                                                    png=PNG_DIR,
                                                    result_file=RESULT_PIECHART_FILE))


def try_load_results(dest_dir, filename):
    """
    Try to load file with results (in json format)

    :param dest_dir: directory with main results (str)
    :param filename: name of file to load from (str)
    :return: result dictionary (dict)
    """
    try:
        with open("{dest}/{json}/{result_file}".format(
                dest=dest_dir,
                json=JSON_DIR,
                result_file=filename)) as f:
            result = json.loads(f.read())
    except EnvironmentError:
        return None

    return result


def write_continents_top(continents):
    """
    Write top continents with count to txt file

    :param continents: dict with continents (dict)
    :return: None
    """
    top_continents_list = ""
    for continent in continents.keys():
        top_continents_list += "Continent: {continent}, found - {count}\n".format(
            continent=continent, count=continents[continent])
        try:
            with open(
                    "{dest}/{txt}/{result_file}".format(
                        dest=RESULTS_DIR,
                        txt=TXT_DIR,
                        result_file=CONTINENTS_TOP_TXT_FILE),
                    mode="w") as file:
                file.write(top_continents_list)
        except FileNotFoundError:
            print("{color}Error: destination file write failed{reset}".format(
                color=ERROR_COLOR, reset=RESET_COLOR))


def count_continents(unique_countries):
    """
    Find all continents based on country name

    :param unique_countries: dict of unique countries {country: count}(dict)
    :return: dict of continents (dict)
    """
    full_names = {
        "AF": "Africa",
        "AN": "Antarctica",
        "AS": "Asia",
        "EU": "Europe",
        "NA": "North America",
        "OC": "Oceania",
        "SA": "South and Central America"
    }

    continents = {}
    for country in unique_countries.keys():
        try:
            cntry_code = country_to_code(country, cn_name_format="default")
            continent_key = code_to_continent(cntry_code)
            continent = full_names[continent_key]
        except KeyError:
            continent = country

        if continent not in continents:
            continents[continent] = unique_countries[country]
        else:
            continents[continent] += unique_countries[country]

    return continents


def create_pie_chart(elements, suptitle, png, figure_id):
    """
    Create pie chart

    :param elements: dict with elements (dict)
    :param suptitle: name of chart (str)
    :param png: name of output file (str)
    :param figure_id: id of current plot (started with 1) (int)
    :return: None
    """
    values = [value for value in elements.values()]
    keys = [key for key in elements.keys()]
    plt.figure(figure_id)
    plt.subplots_adjust(bottom=.05, left=.01, right=.99, top=.90, hspace=.35)

    explode = [0 for x in range(len(keys))]
    max_value = max(values)
    explode[list(values).index(max_value)] = 0.1

    plt.pie(values, labels=keys,
            autopct=make_autopct(values), explode=explode,
            textprops={'fontsize': PIE_LABEL_FONT_SIZE})
    plt.axis("equal")
    plt.suptitle(suptitle, fontsize=PIE_SUPTITLE_FONT_SIZE)

    plt.gcf().set_dpi(PIE_DPI)
    plt.savefig("{dest}/{png}/{result_file}".format(dest=RESULTS_DIR,
                                                    png=PNG_DIR,
                                                    result_file=png))


def count_entries(elements, max_elements, element_name, filename):
    """
    Count every entity that was founded on sd-wan search results.
    Write to txt file.

    :param elements: list of elements (list)
    :param max_elements: maximum elements in dict (int)
    :param element_name: name (type) of counting element (str)
    :param filename: output filename (str)
    :return: sorted by value dict of elements (dict)
    """
    elements_dict = Counter(elements)
    sorted_by_value = dict(
        sorted(elements_dict.items(), key=lambda x: x[1], reverse=True))

    real_max = len(sorted_by_value.keys())
    if max_elements < real_max:
        real_max = max_elements

    full_dict = {key: sorted_by_value[key] for key in list(sorted_by_value)}
    fixed_dict = {key: sorted_by_value[key] for key in
                  list(sorted_by_value)[:real_max]}

    # Write top
    top_elements_list = ""
    for element in fixed_dict.keys():
        top_elements_list += "{type}: {value}, found - {count}\n".format(
            type=element_name, value=element, count=elements_dict[element])
        try:
            with open(
                    "{dest}/{txt}/{result_file}".format(
                        dest=RESULTS_DIR,
                        txt=TXT_DIR,
                        result_file=filename),
                    mode="w") as file:
                file.write(top_elements_list)
        except FileNotFoundError:
            print("{color}Error: destination file write failed{reset}".format(
                color=ERROR_COLOR, reset=RESET_COLOR))

    return fixed_dict, full_dict


def add_hostvuln_to_allvuln(host_vulners, all_vulners):
    """
    Extend main counter of all vulnerabilities with new founded host vulnerabilities

    :param host_vulners: vulnerabilities from new host (list)
    :param all_vulners: list of all vulnerabilities (list)
    :return: None
    """
    if isinstance(host_vulners, list):
        all_vulners.extend(host_vulners)
    elif isinstance(host_vulners, str):
        all_vulners.append(host_vulners)


def vendor_exist(vuln_scan, vendor_name):
    """
    Check if command line argument is findable in our script.

    :param vuln_scan: list of CLI arguments (list)
    :param vendor_name: name of current scanning vendor (str)
    :return: True or False (bool)
    """

    # If we choose all vendors
    if "all" in vuln_scan:
        return True

    for arg_vendor in vuln_scan:
        if arg_vendor.lower() not in vendor_name.lower():
            continue
        else:
            return True

    return False


def vendor_vulners_scan(vendor_name, vendor_vulners, host_vulners):
    """
    Collect vulnerabilities on some vendor

    :param vendor_name: Name of collected vendor (e.g. Silverpeak) (str)
    :param vendor_vulners: dict with vendors and vulnerabilities (dict)
    :param host_vulners: list of host vulnerabilities (list)
    :return: None
    """
    if vendor_name not in vendor_vulners:
        vendor_vulners[vendor_name] = host_vulners
    else:
        add_hostvuln_to_allvuln(host_vulners, vendor_vulners[vendor_name])


def snmp_checker(host_data, ip):
    """
    Check for snmp public services

    :param host_data: data from host (dict)
    :param ip: host ip (str)
    """
    data_list = host_data.get("data")
    if not data_list:
        return
    for service in data_list:
        snmp_service = service.get("snmp")
        if snmp_service:
            print("{color}[+] found SNMP at: {addr}{reset}".format(addr=ip,
                                                                   color=ADD_SNMP_COLOR,
                                                                   reset=RESET_COLOR))
            return "CWE-798"


def host_vulners_scan(api, ip):
    """
    Initiate vulnerabilities scan with shodan api host method

    :param api: shodan api instance
    :param ip: host ip (str)
    :return: list of host vulnerabilities (list)
    """
    time.sleep(REQUEST_DELAY_SLEEP_TIME)

    try:
        host_data = api.host(ip)
    except shodan.exception.APIError as rate_limit_err:
        print(
            "{color}Request limit error (vulnerabilities): {error_info}{reset}".format(
                error_info=rate_limit_err,
                color=ERROR_COLOR,
                reset=RESET_COLOR))
        time.sleep(REQUEST_LIMIT_SLEEP_TIME)
        return host_vulners_scan(api, ip)
    except Exception as unknown_error:
        print(
            "{color}Error: {error_info}{reset}".format(
                error_info=unknown_error, color=ERROR_COLOR,
                reset=RESET_COLOR))
        return

    snmp_vulner = snmp_checker(host_data, ip)

    host_vulners = host_data.get("vulns")
    if snmp_vulner:
        if host_vulners is None:
            host_vulners = []
        host_vulners.append(snmp_vulner)

    if not host_vulners:
        return

    return host_vulners


def new_scan(queries, destination, confidence, shodan_key, vuln_scan):
    """
    Start new scan with shodan and nmap port scanner

    :param queries: dictionary with shodan queries (dict)
    :param destination: destination write directory (str)
    :param confidence: confidence level (str)
    :param shodan_key: key from shodan API (str)
    :param vuln_scan: enable vulnerabilities scan (bool)

    :return result: list with shodan and nmap results (list)
    :return countries: list with countries (list)
    :return all_vulners: list with CVE vulnerabilities (list)
    :return vendor_vulners: dictionary with cve grouped by vend (dict)
    """
    api = shodan.Shodan(shodan_key)
    nm = nmap.PortScanner()

    result_csv = []
    result = []
    countries = []
    all_vulners = []
    vendor_vulners = {}
    prev_vuln_counter = 0

    for query in queries:

        # Confidence levels:
        # certain > firm > tentative
        # certain = certain
        # firm = certain + firm
        # tentative = certain + firm + tentative (all)

        confidence = confidence.lower()
        if confidence == 'certain':
            if query["confidence"] != confidence:
                print(
                    "{color}[-] {product} ignored: confidence level is not equal ({confidence_query} / {confidence_req}){reset}".format(
                        color=PASS_VENDOR_BY_CONFIDENCE_COLOR,
                        product=query["product"],
                        confidence_query=query["confidence"],
                        confidence_req=confidence,
                        reset=RESET_COLOR))
                continue
        elif confidence == 'firm':
            if query["confidence"] not in ['certain', 'firm']:
                print(
                    "{color}[-] {product} ignored: confidence level is not equal ({confidence_query} / {confidence_req}){reset}".format(
                        color=PASS_VENDOR_BY_CONFIDENCE_COLOR,
                        product=query["product"],
                        confidence_query=query["confidence"],
                        confidence_req=confidence,
                        reset=RESET_COLOR))
                continue

        try:
            print("{color}{product} found: {res_count}{reset}".format(
                color=PRODUCT_FOUND_COLOR,
                product=query["product"],
                res_count=api.count(query["query"]).get("total"),
                reset=RESET_COLOR))

            current_result = api.search_cursor(query["query"])

            # Save quantity of vulnerabilities before new query to count it
            if vuln_scan:
                prev_vuln_counter = len(all_vulners)

            # Parse every field from current scanned host
            for result_field in current_result:

                # Check for latitude and longitude
                location = result_field["location"]
                if None in (location["latitude"], location["longitude"]):
                    continue

                # Collect countries for country-chart
                if location["country_name"]:
                    countries.append(location["country_name"])

                # Collect additional host info
                info = str(get_info(nm, query["script"], query["vendor"],
                                    result_field))
                parsed_additional_info = delete_build(info)

                # Collect CVEs if vulnerabilities scan is on
                host_vulners = None
                if vuln_scan:
                    host_vulners = host_vulners_scan(api, result_field.get(
                        "ip_str"))
                    if host_vulners:
                        add_hostvuln_to_allvuln(host_vulners, all_vulners)
                    if host_vulners and vendor_exist(vuln_scan,
                                                     query["vendor"]):
                        print(
                            '{color}[+] found {count} vulnerabilities for {name} from: {address}{reset}'.format(
                                color=ADD_VULNERABILITIES_COLOR,
                                count=len(host_vulners),
                                name=query["vendor"],
                                address=result_field.get("ip_str"),
                                reset=RESET_COLOR))
                        vendor_vulners_scan(query["vendor"], vendor_vulners,
                                            host_vulners)

                # Create result array
                add_to_array(result, result_csv,
                             {
                                 "product": query["product"],
                                 "vendor": query["vendor"],
                                 "port": result_field.get("port"),
                                 "proto": result_field["_shodan"]["module"],
                                 "ip": result_field.get("ip_str"),
                                 "lat": result_field["location"]["latitude"],
                                 "lng": result_field["location"]["longitude"],
                                 "country": location["country_name"],
                                 "vulnerabilities": host_vulners,
                                 "additional_info": parsed_additional_info
                             })

            # Calculate vulnerabilities quantity after new query
            if vuln_scan:
                print(
                    "{color}[!] vulnerabilities found: {count}{reset}".format(
                        color=ADD_VULNERABILITIES_COLOR,
                        count=(len(all_vulners) - prev_vuln_counter),
                        reset=RESET_COLOR
                    ))

        except shodan.exception.APIError as rate_limit_err:
            print("{color}Request limit error: {error_info}{reset}".format(
                color=ERROR_COLOR,
                error_info=rate_limit_err,
                reset=RESET_COLOR))
            # Default timer = 30 sec.
            time.sleep(REQUEST_LIMIT_SLEEP_TIME)
        except Exception as unknown_error:
            print("{color}Error: {error_info}{reset}".format(
                color=ERROR_COLOR,
                error_info=unknown_error,
                reset=RESET_COLOR))
            if not result:
                break

    print("{color}Final result (unique hosts): {result_count}{reset}".format(
        color=ADD_VULNERABILITIES_COLOR,
        result_count=len(result),
        reset=RESET_COLOR))
    print(
        "{color}Final result (unique pairs host and port): {unique_count}{reset}".format(
            color=ADD_VULNERABILITIES_COLOR,
            unique_count=len(result_csv),
            reset=RESET_COLOR))

    write_result_to_file_json(result, destination, RESULT_JSON_FILE)
    write_result_to_file_csv(result_csv, destination)

    return result, countries, all_vulners, vendor_vulners


def create_subdirectory(subdir, dest):
    """
    Create subdirectories for result files

    :param subdir: subdir name (str)
    :param dest: main root result directory (str)
    :return: None
    """
    full_path = "./{dest}/{subdir}".format(dest=dest,
                                           subdir=subdir)
    if not os.path.exists(full_path):
        os.makedirs(full_path)


def create_root_dir(dest):
    """
    Create root directory for results

    :param dest: root dir name (str)
    :return: None
    """
    full_path = "./{dest}".format(dest=dest)
    if not os.path.exists(full_path):
        os.makedirs(full_path)


def update_map_markers(result_data):
    """
    Update markers for SD-WAN map

    :param result_data: results with geo data (latitude, longitude)
    :return: None
    """
    with open("{map_dir}/maps/markers.js".format(map_dir=MAP_MARKERS_DIR),
              mode="w") \
            as markers_js:
        markers_js.write("var markers = {data};".format(data=result_data))


def run(args):
    """
    Main harvester core module

    :return: None
    """

    # ['silver', 'peak,', ' talari,', ...] -> ['silver peak', 'talari', ...]
    if args.vulners:
        parse_arguments = ' '.join(args.vulners).split(',')
        args.vulners = [arg.strip() for idx, arg in
                        enumerate(parse_arguments)]

    # Create directories and subdirectories for output results
    create_root_dir(args.destination)
    for directory in [JSON_DIR, CSV_DIR, TXT_DIR, PNG_DIR]:
        create_subdirectory(directory, args.destination)

    # Try to open .json file with Shodan queries
    try:
        with open(args.queries) as fp:
            queries = json.loads(fp.read())
    except FileNotFoundError as file_error:
        print(
            "{color}Can not find file {file_name}: {error_msg}{reset}".format(
                color=ERROR_COLOR,
                file_name=args.queries,
                error_msg=file_error,
                reset=RESET_COLOR))
        sys.exit(1)

    # Start new scan if new is initiated
    result = None
    countries = None
    vulners = None
    vendor_vulners = None

    if args.new is True:
        result, countries, vulners, vendor_vulners = new_scan(queries,
                                                              args.destination,
                                                              args.confidence,
                                                              args.shodan_key,
                                                              args.vulners)

    # If new scan results is empty or argument not set - load offline results
    if not result:
        result = try_load_results(args.destination, RESULT_JSON_FILE)
        if result is None:
            print("{color}File with results not found. Exit{reset}".format(
                color=ERROR_COLOR, reset=RESET_COLOR))
            sys.exit(1)

    # If no vendor vulnerabilities - load offline json file with vulnerabilities
    if not vendor_vulners:
        vendor_vulners = try_load_results(args.destination,
                                          VULNERS_BY_VENDORS_JSON)
        if vendor_vulners is None:
            print(
                "{color}File with vulnerabilities by vendor not found. Ignored{reset}".format(
                    color=ERROR_COLOR,
                    reset=RESET_COLOR))

    # If no countries results - load offline json file with countries
    if not countries:
        countries = try_load_results(args.destination, COUNTRIES_JSON_FILE)
        if countries is None:
            print(
                "{color}File with countries not found. Ignored{reset}".format(
                    color=ERROR_COLOR, reset=RESET_COLOR))

    if args.vulners:
        # If vulnerabilities is required, but empty - load offline json results
        if not vulners:
            vulners = try_load_results(args.destination, VULNERS_JSON_FILE)
            if vulners is None:
                print(
                    "{color}File with vulnerabilities not found. Ignored{reset}".format(
                        color=ERROR_COLOR,
                        reset=RESET_COLOR))

        # If vulnerabilities loading is succeeded
        if vulners:
            unique_vulners_top, all_unique_vulners = count_entries(
                                            vulners,
                                            args.max_vulners,
                                            "Vulnerability",
                                            VULNERS_TOP_TXT_FILE)
            create_pie_chart(unique_vulners_top, PIE_VULNERABILITIES_TITLE,
                             VULNERS_PIECHART_FILE,
                             VULNERS_PIE_CHART_ID)
            # If new scan is initiated - update json file with new results
            if args.new is True:
                write_result_to_file_json(all_unique_vulners, args.destination,
                                          VULNERS_JSON_FILE)

        # If we got vulnerabilities by vendors - save all results in json
        if vendor_vulners:
            write_result_to_file_json(vendor_vulners, args.destination,
                                      VULNERS_BY_VENDORS_JSON)
            start_id = VULNERS_BY_VENDORS_PIE_CHART_ID
            for vendor in vendor_vulners.keys():
                unique_vendor_top, all_unique_vendors = count_entries(
                                            vendor_vulners[vendor],
                                            args.max_vulners,
                                            "Vulnerability",
                                            vendor + '.txt')
                create_pie_chart(unique_vendor_top,
                                 vendor + " " + PIE_VULNERS_BY_VENDORS_TITLE_ADD,
                                 vendor + '.png',
                                 start_id)
                if args.new is True:
                    # Write jsons for every vendor
                    write_result_to_file_json(all_unique_vendors,
                                              args.destination,
                                              vendor + '.json')
                start_id += 1

    # If countries loading is succeeded
    if countries:
        unique_countries_top, all_unique_countries = count_entries(
                                        countries,
                                        args.max_countries,
                                        "Country",
                                        COUNTRIES_TOP_TXT_FILE)
        create_pie_chart(unique_countries_top, PIE_COUNTRIES_TITLE,
                         COUNTRIES_PIECHART_FILE, COUNTRIES_PIE_CHART_ID)

        # Work on continents, based on countries
        unique_continents = count_continents(all_unique_countries)
        write_result_to_file_json(unique_continents, args.destination,
                                  CONTINENTS_JSON_FILE)
        write_continents_top(unique_continents)
        create_pie_chart(unique_continents, PIE_CONTINENTS_TITLE,
                         CONTINENTS_PIECHART_FILE,
                         CONTINENTS_PIE_CHART_ID)

        # Save to json if this is our new scan result
        if args.new is True:
            write_result_to_file_json(all_unique_countries, args.destination,
                                      COUNTRIES_JSON_FILE)

    # Count products
    if result:
        try:
            product_list = []
            # Make full list of products from results
            for product in result:
                product_list.append(product['product'])

            unique_products_top, all_unique_products = count_entries(
                                        product_list,
                                        args.max_vendors,
                                        "Product",
                                        PRODUCTS_TOP_TXT_FILE)
            write_result_to_file_json(all_unique_products, args.destination,
                                      PRODUCTS_JSON_FILE)
            create_pie_chart(unique_products_top, PIE_PRODUCTS_TITLE,
                             PRODUCTS_PIECHART_FILE,
                             PRODUCTS_PIE_CHART_ID)
        except Exception:
            pass

    try:
        grouped_dict = group_by_version(result)
        grouped_by_ver_res = [
            {
                "vendor": value["vendor"],
                "product": key.split(";")[1],
                "additional_info": key.split(";")[0],
                "ip_list": value["ip_list"],
                "hosts_amount": len(value["ip_list"].split(","))
            } for key, value in grouped_dict.items()
        ]

        write_result_to_file_csv(grouped_by_ver_res, args.destination,
                                 GROUPED_BY_VERSION_FILE)

        create_top_and_chart(result, args.max_vendors, args.destination)
    except Exception:
        pass

    # Update map markers if needed
    if result and args.update_markers:
        update_map_markers(result)
