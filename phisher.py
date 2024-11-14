import requests
import warnings
import json
import re

from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

from APIkeys import PhishER_APIkey
def phisher_(id):
  url = 'https://training.knowbe4.com/graphql'
  headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'authorization': f'{PhishER_APIkey}'
  }

  query = query = f'''
    query {{
    phisherMessage(id: "{id}") {{
      actionStatus
      attachments {{
        actualContentType
        filename
        md5
        reportedContentType
        s3Key
        sha1
        sha256
        size
        ssdeep
      }}
      category
      comments {{
        body
        createdAt
      }}
      events {{
        causer
        createdAt
        eventType
        id
        triggerer
      }}
      from
      headers {{
        data
        header
        order
      }}
      id
      links {{
        dispositions
        firstSeen
        id
        lastSeen
        scheme
        target
        url
      }}
      phishmlReport {{
        confidenceClean
        confidenceSpam
        confidenceThreat
      }}
      pipelineStatus
      rawUrl
      reportedBy
      rules {{
        createdAt
        description
        id
        matchedCount
        name
        tags
      }}
      severity
      subject
      tags {{
        name
        type
      }}
    }}
  }}
'''
  print('DEBUG: we got query: ', id)

  FINAL_OUTPUT =''
  performable_actions = {}
  response = requests.post(url, headers=headers, json={'query': query}, verify=False)
  response = json.loads(response.text)
  #parsed = json.dumps(response, indent=4, sort_keys=True)
  #print(parsed)


  # Extract the relevant information
  base_msg = response['data']['phisherMessage']

  #data for headers and sender IP
  try:
    for i in base_msg['headers']:
      if any(header in i['data'] for header in ['Sender IP', 'spf', 'dkim', 'dmarc', 'compauth']) and i['header'] == 'Authentication-Results':
          headers = i['data']
          break
  except:
    headers = 'Headers not found in the email'
    
  #print('HEADERS : ', headers)
  #---------------------------------------------------------------------

  #CLOSING NOTES START
  # --- code ---

  #.1
  #Sender IP:
  print('Started ip section')

  sender_ip = re.search(r'sender IP is ((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})', headers)
  #sender_ip = '8.219.51.255'
  if sender_ip:
      sender_ip = sender_ip.group(1)
  #print(f"SENDER IP: {sender_ip}")
  if sender_ip != None:
    FINAL_OUTPUT += f"SENDER IP: {sender_ip}\n"
  else:
    FINAL_OUTPUT += 'Sender IP: not found in the email\n'

  if sender_ip != None: 
    print('SENDER IP INSIDE IF CHECK')
  #scanning IPs on VT, OTX, Talos, AbuseIPDB
    from VT import VT_scan_ip
    from OTX import OTX_ip_scan
    from talos import Talos_ip_scan
    from AbuseDB import abuseDB_ip_scan

    #print(OTX_ip_scan(sender_ip))
    #print(Talos_ip_scan(sender_ip))
    #print(abuseDB_ip_scan(sender_ip))
    #print(VT_scan_ip(sender_ip))
    otx_ip = OTX_ip_scan(sender_ip) 
    #print('OTX IP : ', otx_ip)
    FINAL_OUTPUT += otx_ip + '\n'
    talos_ip = Talos_ip_scan(sender_ip)
    #print('TALOS IP : ', talos_ip)
    FINAL_OUTPUT += talos_ip + '\n'
    abuse_ip = abuseDB_ip_scan(sender_ip)
    #print('ABUSE IP : ', abuse_ip)
    FINAL_OUTPUT += abuse_ip + '\n'
    vt_ip = VT_scan_ip(sender_ip)
    #print('VT IP : ', vt_ip)
    FINAL_OUTPUT += vt_ip + '\n'    
    
    ip_mal = 0 #to check if ip needs human intervention
    #print('ip_mal : ', ip_mal)
    #print('IP OTX FIND : ', int(otx_ip[otx_ip.find('count: ')+7]))
    if 'malicious' in otx_ip or int(otx_ip[otx_ip.find('count: ')+7]) >= 5:
       ip_mal += 1
       print('otx_ip malicious check added : ', otx_ip)
    if 'favourable' not in talos_ip or 'neutral' not in talos_ip:
       ip_mal += 1
       print('talos_ip malicious check added : ', talos_ip)
    if int(abuse_ip[abuse_ip.find('score: ')+7:]) >=12:
        ip_mal += 1
        print('abuse_ip malicious check added : ', abuse_ip)
    if 'clean' not in vt_ip:
        ip_mal += 1
        print('vt_ip malicious check added : ', vt_ip)
    print('IP MALICIOUS COUNT : ', ip_mal)
    
    if ip_mal >= 2:
        #FINAL_OUTPUT += 'IP needs human intervention\n'
        performable_actions['ip'] = 'IP seems malicious and hence needs human intervention'
        #print('PERFORMABLE ACTIONS updated in ip: ', performable_actions)

    #print('PERFORMABLE ACTIONS updated in ip: ', performable_actions)

  print('done in ip sectoin')
  #--------------------------------------------------------------------

  #.2
  #Sender Domain:
  print('start in domain')
  try: 
    sender_mail = base_msg['from']
    sender_domain = sender_mail.split('@')[1]
    print(f"SENDER DOMAIN: {sender_domain}")

    #testing part (hardcoded sender domain)
    #only uncomment next line for testing [ required action testing ] :)
    #sender_domain = 'sync.smart-vnc.com'

    FINAL_OUTPUT += f"SENDER DOMAIN: {sender_domain}\n"

    from VT import VT_scan_domain
    from OTX import OTX_domain_scan
    from talos import Talos_domain_url

    #print(OTX_domain_scan(sender_domain))
    #print(Talos_domain_url(sender_domain))
    #print(VT_scan_domain(sender_domain))
    #print('')
    otx_domain = OTX_domain_scan(sender_domain)
    FINAL_OUTPUT += otx_domain + '\n'
    talos_domain = Talos_domain_url(sender_domain)
    FINAL_OUTPUT += talos_domain + '\n'
    vt_domain = VT_scan_domain(sender_domain)
    FINAL_OUTPUT += vt_domain + '\n'
    FINAL_OUTPUT += '\n'

    #to check if domain needs human intervention
    domain_mal = 0
    if int(otx_domain[otx_domain.find('count: ')+7]) >=5:
       domain_mal += 1
    if not 'favourable' in talos_domain or 'neutral' in talos_domain:
       domain_mal += 1
    if not 'clean' in vt_domain:
       domain_mal += 1
    
    if domain_mal > 1:
        #FINAL_OUTPUT += 'IP needs human intervention\n'
        performable_actions['domain'] = 'Domain seems malicious and hence needs human intervention'

  except:
    #print('Sender domain: not found in the email') 
    #print('')
    FINAL_OUTPUT += 'Sender domain: not found in the email\n\n'
    #print(base_msg['from'], len(base_msg['from']))
    #ref: INC0971262, INC0971261
  print('done in domain')

  #---------------------------------------------------------------------

  #.3
  #URL(s) found malicious/clean -
  print('start with url search')
  #print('URL(s) RESULT: ')
  FINAL_OUTPUT += 'URL(s) RESULT: \n'
  links = base_msg['links']
  links_target = []

  white_list_domains = ['https://aka.ms', 'https://nam04.safelinks.protection.outlook.com', 'https://w3.org']
  for link_dict in links:
      if isinstance(link_dict, dict) and 'target' in link_dict:
          _tmp = link_dict['target']
          if not any(_tmp.startswith(domain) for domain in white_list_domains):
              links_target.append(_tmp)
  #print(f"Links: {links}")
  if len(links_target) == 0:
      #print('No URLs found in the email\n')
      FINAL_OUTPUT += 'No URLs found in the email\n'
  else:
    #URL DECODE
    from urllib.parse import unquote
    links_target = [unquote(link) for link in links_target]
    #print(f"Links: {links_target}")
    
    #testing (hardcoded url)
    #only uncomment next line for testing [ required action testing ] :)
    #links_target = ['https://www.google.com/', 'https://sync.smart-vnc.com/', 'https://serak.top/']

    from VT import VT_scan_urls
    url_mal_count = 0
    for i in links_target:
      vt_url = VT_scan_urls([i])
      if not 'clean' in vt_url:
          url_mal_count += 1
      FINAL_OUTPUT += vt_url + '\n'
    
    if url_mal_count >=1:
        #FINAL_OUTPUT += 'URL(s) needs human intervention\n'
        performable_actions['url'] = f'{url_mal_count}/{len(links_target)} result(s) malicious and hence needs human intervention'

    #FINAL_OUTPUT += VT_scan_urls(links_target)
    #print('')
  
  #FINAL_OUTPUT += '\n'
  print('done with url search')
  #--------------------------------------------------------------------

  #.4
  #Attachment(s) found malicious/clean -
  print('start with attachment search')
  from VT import VT_scan_files

  #print('ATTACHMENTS: ')
  FINAL_OUTPUT += 'ATTACHMENTS: \n'

  attachments = base_msg['attachments']
  if len(attachments) == 0:
      #print('No attachments found in the email\n')
      FINAL_OUTPUT += 'No attachments found in the email\n'
  else:
    _filecount = 0 #to check how many file hash exist in vt 
    for attachment in attachments:
      #print('filename:', attachment['filename'])
      #print(VT_scan_files(attachment['sha256']))
      FINAL_OUTPUT += f"filename: {attachment['filename']}\n"
      vt_file = VT_scan_files(attachment['sha256']) + '\n'
      #print('\nFIle vt data : ', vt_file, '\n')
      if 'File hash not found' in vt_file:
          _filecount += 1
      FINAL_OUTPUT += vt_file + '\n'

    if _filecount >= 1:
        #FINAL_OUTPUT += 'Attachment(s) needs human intervention\n'
        performable_actions['attachment'] = f'{_filecount}/{len(attachments)} file hash(es) not found, attachment needs human intervention'
        #print('PERFORMABLE ACTIONS updated in attachments: ', performable_actions)
         

      #print('sha256:', attachment['sha256'])

  #print('')
  #FINAL_OUTPUT += '\n'
  print('done with attachment search')

  #---------------------------------------------------------------------

  #.5 
  #Headers-
  print('start with headers')
  #print('HEADERS: ')
  FINAL_OUTPUT += 'HEADERS: \n'

  if headers != 'Headers not found in the email':
    patterns = {
        'spf': r'spf=(\w+)',
        'dkim': r'dkim=(\w+)',
        'dmarc': r'dmarc=(\w+)',
        'compauth': r'compauth=(\w+)'
    }
    extracted_values = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, headers)
        if match:
            extracted_values[key] = match.group(1)
    for key, value in extracted_values.items():
        #print(f"{key}: {value}")
        FINAL_OUTPUT += f"{key}: {value}\n"
  else:
    #print(headers)
    FINAL_OUTPUT += headers + '\n'
  #print('')
  print('done with headers')
  #---------------------------------------------------------------------

  #<> get email body,
  from rawurl import extract_email_body
  res_email = requests.get(base_msg['rawUrl'], verify=False)
  get_email_body = extract_email_body(res_email.text)
  print('EMAIL BODY : ', get_email_body)
  
  
  #---------------------------------------------------------------------
  #-- done --
  return {'FINAL_OUTPUT': FINAL_OUTPUT, 'email_body_result': get_email_body }, performable_actions

'''
  #---------------------------------------------------------------------

  #.6 
  #Email body review shows the email to be phish/clean/spam.
  print('start with email body review')
  _final_result = base_msg['category']
  #print('Email body review shows the email to be', _final_result)
  FINAL_OUTPUT += f'Email body review shows the email to be {_final_result}\n'
  print('done with email body review')
  #---------------------------------------------------------------------

  #.7 rest msg
  if _final_result == 'SPAM':
     
      #print('Action taken: No further action required ')
      #print('Nature of incident – True positive')
      #print('Marked email as Spam')
      FINAL_OUTPUT += 'Action taken: No further action required\nNature of incident – True positive\nMarked email as Spam\n'
'''

