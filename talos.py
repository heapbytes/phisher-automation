#no api needed (the webpage was taking data from following URLs)
import requests
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

def Talos_domain_url(URL):
    url = f'https://talosintelligence.com/cloud_intel/url_reputation?url={URL}'

    response = requests.get(url=url, verify=False).json()
    #print(response)

    return 'Talos results: ' + response["reputation"]["threat_level_mnemonic"]


def Talos_ip_scan(IP):
    #https://talosintelligence.com/cloud_intel/sds_lookup?hostname=SDSv3&query_string=%2Fscore%2Fsingle%2Fjson%3Fip%3D149.50.109.188
    url = f'https://talosintelligence.com/cloud_intel/ip_reputation?ip={IP}'
    response = requests.get(url=url, verify=False).json()
    #print(response)

    return 'Talos results: ' + response["reputation"]["threat_level_mnemonic"]


if __name__ == '__main__':
    print(domain_url('bd.mediasolz.com'))
    #print(ip_scan('142.44.149.54'))
    #print(domain_url('https://google.com/'))
