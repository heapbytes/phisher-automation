from OTXv2 import OTXv2
import APIkeys

import requests
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

 # Replace with one of: 'general', 'geo', 'malware', 'url_list', 'passive_dns'

def OTX_domain_scan(domain):
    #print('OTX SCANNING FOR DOMAIN : ', domain)
    section = 'general' 
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/{section}'
    headers = {
        'X-OTX-API-KEY': APIkeys.OTX_APIkey,
        'Accept': 'application/json'
    }

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = response.json()
        #return data
                
        if 'pulse_info' in data:
            pulse_count = data['pulse_info'].get('count', 0)
            return f"OTX result: pulse count: {pulse_count}"
        else:
            return f"No pulse data found for {domain}."


    else:
        print(f"Failed to fetch data: {response.status_code}")
        return {}

def url_scan(url_):
    section = 'general' 
    url = f'https://otx.alienvault.com/api/v1/indicators/url/{url_}/{section}'
    print(url)
    # api/v1/indicators/url/http://www.fotoidea.com/

    headers = {
        'X-OTX-API-KEY': APIkeys.OTX_APIkey,
        'Accept': 'application/json'
    }

    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = response.json()
        #print(data)                
        if 'pulse_info' in data:
            pulse_count = data['pulse_info'].get('count', 0)
            return f"Number of pulses for {url_}: {pulse_count}"
        else:
            return f"No pulse data found for {url_}."
    else:
        print(f"Failed to fetch data: {response.status_code}")
        return {}
    

def OTX_ip_scan(IP):
    section='general'

    '''sections for ipv4:
    general: General information about the IP, such as geo data, and a list of the other sections currently available for this IP address.
    reputation: OTX data on malicious activity observed by LevelBlue Labs (IP Reputation).
    geo: A more verbose listing of geographic data (Country code, coordinates, etc.)
    malware: Malware samples analyzed by LevelBlue Labs which have been observed connecting to this IP address.
    url_list: URLs analyzed by LevelBlue Labs which point to or are somehow associated with this IP address.
    passive_dns: passive dns information about hostnames/domains observed by LevelBlue Labs pointing to this IP address.
    http_scans: Meta data for http(s) connections to the IP.
    '''

    urlv4 = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{IP}/{section}'
    urlv6 = f'https://otx.alienvault.com/api/v1/indicators/IPv6/{IP}/{section}'

    
    #api/v1/indicators/IPv4/8.8.8.8/general
    headers = {
        'X-OTX-API-KEY': APIkeys.OTX_APIkey,
        'Accept': 'application/json'
    }

    #check if url is ipv4 or ipv6
    #not a neat algo, but who cares, it works!!
    if '.' in IP and ':' not in IP:
        response = requests.get(urlv4, headers=headers,verify=False)
        #print('IPV4 detected')
    elif ':' in IP and '.' not in IP:
        response = requests.get(urlv6, headers=headers, verify=False)
        #print('IPv6 detected')
    else:
        return "Invalid IP"

    if response.status_code == 200:
        data = response.json()
        #print(data)
        if 'pulse_info' in data:
            pulse_count = data['pulse_info'].get('count', 0)
            #return f"Number of pulses for {IP}: {pulse_count}"
            if pulse_count >= 5:
                return f"OTX result: pulse count: {pulse_count}"
            else:
                return f"OTX result: pulse count: {pulse_count}"
        else:
            return f"OTX result: No pulse data found for {IP}."

    else:
        print(f"Failed to fetch data: {response.status_code}")
        return {}


if __name__ == "__main__":
    DOMAIN = 'bd.mediasolz.com'
    IP='192.42.116.219'
    URL='https://www.google.com'
    print(domain_scan(DOMAIN))
