import requests
import urllib3
import concurrent.futures
from tabulate import tabulate
import sys
import subprocess


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

heads = {"X-Hackerone-Researcher" : "YOUR_USER_NAME"}


conworkers = 10

sub_file = str(sys.argv[1])
output_folder = str(sys.argv[2])


subdomains_list = []
status_dict = {}

valid_urls = []


# Check HTTP status
def check_http_status(sub):
    try:
        http_response = requests.get('http://' + sub.rstrip(), headers=heads, timeout=30)
        return str(http_response.status_code)
    except requests.exceptions.RequestException as e:
        return "exception"

# Check HTTPs status
def check_https_status(sub):
    try:
        https_response = requests.get('https://' + sub.rstrip(), headers=heads, timeout=30, verify=False)
        return str(https_response.status_code)
    except requests.exceptions.RequestException as e:
        return "exception"



# Creating status checking threads
def http_check_threading():
    subdoms = open('subs.txt', 'r')
    for subdom in subdoms:
        subdomains_list.append(subdom.rstrip())

    for i in subdomains_list:
        status_dict[i] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=conworkers) as executor:
        future_http = {executor.submit(check_http_status, subdom) : subdom for subdom in subdomains_list}
        for future in concurrent.futures.as_completed(future_http):
            domain = future_http[future].rstrip()
            try:
                status_dict[domain]['http'] = future.result()
            except Exception as e:
                print(f'Error during {domain} exception: {e}')
        
        future_https = {executor.submit(check_https_status, subdom) : subdom for subdom in subdomains_list}
        for future in concurrent.futures.as_completed(future_https):
            domain = future_https[future].rstrip()
            try:
                status_dict[domain]['https'] = future.result()
            except Exception as e:
                print(f'Error during {domain} exception: {e}')


# Printing the output table and writing it into output file [OUTPUT_FOLDER]/subout.txt
def perform_http_check():
    http_check_threading()
    table_data = []
    table_heads = ["SubDomain", "HTTP", "HTTPS"]

    # appending data to table and making a list of valid_urls
    for dom, prtcol in status_dict.items():
        table_data.append([dom, prtcol['http'], prtcol['https']])
        if prtcol['http'] != 'exception':
            valid_urls.append("http://" + dom)
        if prtcol['https'] != 'exception':
            valid_urls.append("https://" + dom)

    table_str = tabulate(table_data, headers=table_heads, tablefmt='grid')

    print(table_str)

    try:
        with open(output_folder + '/subout.txt', "w", encoding="utf-8") as f:
            f.write(table_str)
            f.write('\n\n\n' + str(status_dict))
        print(f'Table successfully written to {output_folder}/subout.txt')
    except IOError as e:
        print(f"Error writing to file: {e}")


def main():
    perform_http_check()


if __name__ == "__main__":
    main()
