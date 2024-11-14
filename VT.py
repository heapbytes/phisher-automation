ximport requests
import hashlib
import APIkeys
import warnings
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)
#https://www.ipqualityscore.com/user/dashboard
#https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview

def loop_check(res):
    _malFlag = 0
    _spamFlag = 0
    count = 0 
    for vendor, vendor_data in res.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).items():
        count += 1
        _cleanStat = vendor_data.get("result")
        
        if _cleanStat:
            if _cleanStat.lower() in ["malicious", "suspicious", "phishing", "malware"]:
                _malFlag += 1
            elif _cleanStat.lower() not in ["clean", "unrated", "harmless"]:
                _spamFlag += 1

    return _malFlag, _spamFlag, count

def resolve_url(url):
    # Regular expression to check for valid top-level domains
    if '#' in url:
        url = url.split('#')[0]
    tld_pattern = re.compile(r'\.[a-z]{2,}$')
    if tld_pattern.search(url):
        if not url.endswith('/'):
            url += '/'
    
    return url

def VT_analyse_url(scan_url):
    url = "https://www.virustotal.com/api/v3/urls"
    #scan_url = "http://click.mailchimp.com/track/click/30010842/www.mailchimp.com?p=NzRjssdffsdtysdfyyf5dfg4vffdsdfsdssYWYwXCJdf"

    payload = { "url": f"{scan_url}" }
    headers = {
        "accept": "application/json",
        "x-apikey": APIkeys.VirusTotal_APIkey,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers, verify=False)
    #print(response.text)
    #print(response.text)

    response = response.json()
    #scan_id = response['data']['id']
    #print('SCAN ID : ', scan_id)

    sha256_url = hashlib.sha256(f'{scan_url}'.encode()).hexdigest()
    url = f"https://www.virustotal.com/api/v3/urls/{sha256_url}"

    headers = {
        "accept": "application/json",
        "x-apikey": APIkeys.VirusTotal_APIkey
    }
    import time
    time.sleep(2)
    response = requests.get(url, headers=headers, verify=False)
    return response.json()
    #return response.json()

def VT_scan_urls(URLs):
    #print(URLs)
    for URL in URLs:
        #print(URL)

        URL = resolve_url(URL)
        final_msg = ''
        sha256_url = hashlib.sha256(URL.encode()).hexdigest()
        url = "https://www.virustotal.com/api/v3/urls/" + sha256_url #+ "/votes"
        #print(url)

        headers = {
            "accept": "application/json",
            "x-apikey": APIkeys.VirusTotal_APIkey
        }

        try:
            res = requests.get(url, headers=headers, verify=False)
            #print('outside if : ',res.text)
            res = res.json()
            if res['error']['code'] == 'NotFoundError':
                #print('INSIDE IF ERROR NOT FOUND')

                res = VT_analyse_url(URL)
                #print(res)
                #print('Mannual intervation required for : ', URL)
                #continue
        except:
            pass

        # flag for malicious, if 0, url is safe, if 1 and more, some vendor marked it as malicious/suspicious
#        print(res)
        try:
            _malFlag, _spamFlag, count = loop_check(res)
            if _malFlag >= 5:
                final_msg += f'{URL[:25] +'\nhttps://www.virustotal.com/gui/url/' + sha256_url}\nVT result: malicious (score - {_malFlag}/{count})\n'
            elif _spamFlag >= 5:
                final_msg += f'{URL[:25] +'\nhttps://www.virustotal.com/gui/url/' + sha256_url}\nVT result: spam (score - {_spamFlag}/{count})\n'
            else:
                final_msg += f'{URL[:25] +'\nhttps://www.virustotal.com/gui/url/' + sha256_url},\nVT result: clean\n'
            
            #print('')

            #print(final_msg)
            return final_msg
        except:
            if res['error']['code'] == 'InvalidArgumentError':
                #print('\nUnable to canonicalize url on VT: ', URL)
                return '\nUnable to canonicalize url on VT, ' + URL
            #print('\nURL not found in VT database: ', URL)
            return '\nURL not found in VT database, ' + URL


def VT_scan_domain(domain) -> str:
    url = "https://www.virustotal.com/api/v3/domains/" + domain #+ "/votes"
    #print(url)

    headers = {
        "accept": "application/json",
        "x-apikey": APIkeys.VirusTotal_APIkey
    }

    res = requests.get(url, headers=headers, verify=False)
    res = res.json()
    #print(res)

    # flag for malicious, if 0, url is safe, if 1 and more, some vendor marked it as malicious/suspicious
    #_malVendor = []
    try:
        _malFlag, _spamFlag, count = loop_check(res)
    except:
        print('Domain not found in VT database: ', domain)

    if _malFlag >= 5:
        final_msg = f'VT result: {domain} is malicious, score=({_malFlag}/{count})\nVT Link- https://www.virustotal.com/gui/domain/{domain}'
    elif _spamFlag >= 5:
        final_msg = f'VT result: {domain} is spam, score=({_malFlag}/{count})\nVT Link- https://www.virustotal.com/gui/domain/{domain}'
    elif _malFlag + _spamFlag >= 5:
        final_msg = f'VT result: {domain} is suspicious, score=({_malFlag}/{count})\nVT Link- https://www.virustotal.com/gui/domain/{domain}'
    else:
        final_msg = f'VT result: {domain} is clean\nVT Link- https://www.virustotal.com/gui/domain/{domain}'

    return final_msg



def VT_scan_ip(IP):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IP}"
    #print(url)

    headers = {
        "accept": "application/json",
        "x-apikey": APIkeys.VirusTotal_APIkey
    }

    res = requests.get(url, headers=headers, verify=False)
    res = res.json()
    #print(res)

    # flag for malicious, if 0, url is safe, if 1 and more, some vendor marked it as malicious/suspicious
    _malFlag, _spamFlag, count = loop_check(res)

    if _malFlag >= 5:
        final_msg = f'VT result: malicious, score={_malFlag}/{count}\nVT Link - https://virustotal.com/gui/ip-address/{IP}\n'
    elif _spamFlag >= 5:
        final_msg = f'VT result: spam, score={_spamFlag}/{count}\nVT Link - https://virustotal.com/gui/ip-address/{IP}\n'
    elif _malFlag + _spamFlag >= 5:
        final_msg = f'VT result: suspicious, score=({_malFlag+_spamFlag, '/',count})\nVT Link- https://www.virustotal.com/gui/domain/{IP}'
    else:
        final_msg = f'VT result: clean\nVT Link - https://virustotal.com/gui/ip-address/{IP}\n'

    return final_msg

def VT_scan_files(hash):
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    headers = {
        "accept": "application/json",
        "x-apikey": APIkeys.Virustotal_APIKey
    }

    res = requests.get(url, headers=headers, verify=False)
    res = res.json()
    #print(res)

    # flag for malicious, if 0, url is safe, if 1 and more, some vendor marked it as malicious/suspicious

    if res.get("error"):
        return "VT result: File hash not found\n"
    else:
        _malFlag, _spamFlag, count = loop_check(res)

        if _malFlag >= 5:
            final_msg = f'VT Link -https://www.virustotal.com/gui/file/{hash}\nVT result: malicious, score={_malFlag}/{count}\n'
        elif _spamFlag >= 5:
            final_msg = f'VT Link - https://www.virustotal.com/gui/file/{hash}\nVT result: spam, score={_spamFlag}/{count}\n'
        elif _malFlag + _spamFlag >= 5:
            final_msg = f'VT Link- https://www.virustotal.com/gui/file/{hash}VT result: {hash} is suspicious, score=({_malFlag+_spamFlag, '/',count})\n'
        else:
            final_msg = f'VT Link - https://www.virustotal.com/gui/file/{hash}\nVT result: clean\n'

        return final_msg



if __name__ == '__main__':

    #check = ['http://wt.mail.from/FromAddress']
    #print(VT_scan_urls(check))
    #print(VT_scan_domain('rebistars.com'))
    print(VT_scan_ip('40.95.110.176'))
# 2908a24263507c59aa75edc0722a1ea34fb20a5849ae8af3cd5d69d571cf0ae9
