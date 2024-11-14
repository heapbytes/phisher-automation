from APIkeys import PhishER_APIkey
import requests
import warnings

from requests.packages.urllib3.exceptions import InsecureRequestWarning
# Suppress InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

def update_mutation(emailid, category):
    f = f'''mutation {{
    phisherMessageUpdate(id: "{emailid}", payload: {{ 
        category: {category},
        status: RESOLVED
    }}) {{
        errors {{
            field
            placeholders
            reason
            recordId
        }}
        node {{
            actionStatus
            category
            from
            id
            pipelineStatus
            rawUrl
            reportedBy
            severity
            subject
        }}
    }}
    }}'''
    
    
    url = 'https://training.knowbe4.com/graphql'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'{PhishER_APIkey}'
    }

    response = requests.post(url, headers=headers, json={'query': f}, verify=False)
    print(response.json())
    print('\nmutation update status code: ', response.status_code)

    return response.json(), response.status_code


if __name__ == '__main__':
    emailid = input('Enter the email id: ')
    update_mutation(emailid, 'CLEAN')