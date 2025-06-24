import requests
import urllib3
import concurrent.futures
from tabulate import tabulate
import sys
from urllib.parse import quote
import tqdm


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

heads = {"X-HackerOne-Research" : "YOUR_USER_NAME"}

sub_file = str(sys.argv[1])
output_folder = str(sys.argv[2])


subdomains_list = []
status_dict = {}
fake_resp_code = [404]


# # # # # # # # # # #
# subdomains search #
# # # # # # # # # # #
# Do your subdomain research with OWASP Amass




# # # # # # # # # 
# HTTP Probing  #
# # # # # # # # #
def check_http_status(sub):
    try:
        http_response = requests.get('http://' + sub.rstrip(), headers=heads, timeout=20)
        return str(http_response.status_code)
    except requests.exceptions.RequestException as e:
        return "exception"

# Check HTTPs status
def check_https_status(sub):
    try:
        https_response = requests.get('https://' + sub.rstrip(), headers=heads, timeout=20, verify=False)
        return str(https_response.status_code)
    except requests.exceptions.RequestException as e:
        return "exception"



# Creating status checking threads
def http_check_threading(subfile):
    subdoms = open(subfile, 'r')
    for subdom in subdoms:
        subdomains_list.append(subdom.rstrip())

    for i in subdomains_list:
        status_dict[i] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_http = {executor.submit(check_http_status, subdom) : subdom for subdom in subdomains_list}
        for future in concurrent.futures.as_completed(future_http):
            domain = future_http[future].rstrip()
            try:
                status_dict[domain]['http'] = future.result()
            except Exception as e:
                print(f'Error during {domain} exception: {e}')
        
        future_https = {executor.submit(check_https_status, subdom) : subdom for subdom in subdomains_list}
        for future in tqdm.tqdm(concurrent.futures.as_completed(future_https), total=len(subdomains_list), desc="Probing HTTP(s) -->"):
            domain = future_https[future].rstrip()
            try:
                status_dict[domain]['https'] = future.result()
            except Exception as e:
                print(f'Error during {domain} exception: {e}')


# Printing the output table and writing it into output file [OUTPUT_FOLDER]/subout.txt
def perform_http_check(subfile):
    valid_urls = []
    http_check_threading(subfile)
    try:
        with open(output_folder + '/probes.csv', "w", encoding="utf-8") as f:
            f.write("SubDomain,HTTP,HTTPS\n")
            for dom, prtcol in status_dict.items():
                if prtcol['http'] != 'exception':
                    valid_urls.append("http://" + dom)
                if prtcol['https'] != 'exception':
                    valid_urls.append("https://" + dom)    
                f.write(dom + ',' + prtcol['http'] + ',' + prtcol['https'] + '\n')
        # print(f'Table successfully written to {output_folder}/probes.csv')
    except IOError as e:
        print(f"Error writing to file: {e}")
    return valid_urls




# # # # # # # # # # # # # #
# Directory bruteforcing  #
# # # # # # # # # # # # # #

def fetcher(url, payload):
    try:
        fetcher_resp = requests.get(url + "/" + quote(payload), headers=heads, timeout=20)
        return fetcher_resp.status_code
    except requests.exceptions.RequestException as e:
        return "fetcherexception"


# Buster function works like gobuster
def buster(url, wordslist):
    outdict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_words = {executor.submit(fetcher, url, payload) : payload for payload in wordslist}
        for future in tqdm.tqdm(concurrent.futures.as_completed(future_words), total=len(wordslist), leave=False, desc=f'{url} Busting Progress -->'):
            payload = future_words[future].rstrip()
            try:
                busting_res = future.result()
                if busting_res != "fetcherexception" and busting_res not in fake_resp_code:
                    outdict[url + "/" + quote(payload)] = str(busting_res)
            except Exception as e:
                print(f'Error during {payload} exception: {e}')
    return outdict


# Bustout function uses above buster function and writes output to stdout and output file
def bustout(url, wordslist):
    # fake_resp = 0
    # cleaning url
    if url.endswith('/'):
        url = url.rstrip('/')
    
    
    outdict = buster(url, wordslist) # This is the usage of above buster function
    
    # Printing and writing to file
    thisurl = url.replace("://", "-").replace("/", "-")
    outfile = open(output_folder + '/' + thisurl + '.csv', "a", encoding="utf-8")
    for finalurl, statuscode in outdict.items():
        try:
            outfile.write(finalurl + "," + statuscode + '\n')
        except IOError as e:
            print(f'Error writing to file {thisurl}.csv: {e}')
    return True


def allbustout(subfile, wordlist):
    urllist = perform_http_check(subfile)
    # wordlist to python list "wordslist"
    wordfile = open(wordlist, 'r')
    wordslist = []
    for i in wordfile:
        wordslist.append(i.rstrip())
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_urls = {executor.submit(bustout, urlitem, wordslist) : urlitem for urlitem in urllist}
        for future in tqdm.tqdm(concurrent.futures.as_completed(future_urls), total=len(urllist), leave=True, desc=f'Total Busting -->'):
            current_url = future_urls[future].rstrip()
            try:
                busting_result = future.result()
            except Exception as e:
                print(f'Error during busting {current_url} exception: {e}')




def main():
    mywordlist = sys.argv[3]
    allbustout(sub_file, mywordlist)

if __name__ == "__main__":
    main()
