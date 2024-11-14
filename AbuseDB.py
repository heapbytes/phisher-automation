import requests
import APIkeys

def abuseDB_ip_scan(IP):
    url = f'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
    "ipAddress": f"{IP}",
    "maxAgeInDays": "90",
    "verbose": ""
    }
    headers = {
        'Key' : APIkeys.AbuseDB_APIkey,
        'Accept': 'application/json'
    }

    f = requests.get(url=url, headers=headers, verify=False, params=querystring).json()
    return 'AbuseDB score: ' + str(f['data']['abuseConfidenceScore'])


#print(scan_ip('192.42.116.219'))