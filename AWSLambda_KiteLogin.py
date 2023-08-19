import requests
import pyotp
import json
import boto3
import time
import hashlib

# Access Kite Credentials securely from AWS Parameters Store
ssm = boto3.client('ssm', 'ap-south-1')

apiKey    = ssm.get_parameter(Name='/kite/apiKey',WithDecryption=True)['Parameter']['Value']
apiSecret = ssm.get_parameter(Name='/kite/apiSecret',WithDecryption=True)['Parameter']['Value']
userID    = ssm.get_parameter(Name='/kite/userID',WithDecryption=True)['Parameter']['Value']
pwd       = ssm.get_parameter(Name='/kite/pwd',WithDecryption=True)['Parameter']['Value']
totpKey   = ssm.get_parameter(Name='/kite/totpKey',WithDecryption=True)['Parameter']['Value']

login_url   = "https://kite.zerodha.com/api/login"
kiteDev_url = 'https://kite.zerodha.com/connect/login?v=3&api_key='+apiKey
twofa_url   = "https://kite.zerodha.com/api/twofa"


def lambda_handler(event, context):
    session = requests.Session()
    
    print('Login Attempt..')
    response = session.post(login_url,data={'user_id':userID,'password':pwd})
    request_id = json.loads(response.text)['data']['request_id']
    print('Login Response: '+ 'Success' if response.status_code==200 else 'Error in Login to Kite')
    
    print('TOTP Attempt..')
    twofa_pin = pyotp.TOTP(totpKey).now()
    response_totp = session.post(twofa_url,data={'user_id':userID,'request_id':request_id,'twofa_value':twofa_pin,'twofa_type':'totp'})
    print('TOTP response: '+ 'Success' if response_totp.status_code==200 else 'Error in Twofa Login to Kite')
    
    #Get Request Token
    response_req_tok =   session.get(kiteDev_url)
    print(response_req_tok)
    request_token = response_req_tok.url.split('request_token=')[1].split(' ')[0].split('&action')[0]
    print('Request Token:{}'.format(request_token))
    
    print('Updating Access Token..')
    access_token_status = get_access_token(request_token)
    
    if access_token_status=='Success':
        time.sleep(2)
        accessToken_LMD = ssm.get_parameter(Name='/kite/accessToken', WithDecryption=True)['Parameter']['LastModifiedDate']
        print('Access Token Successully Modified on: '+ str(accessToken_LMD))
    else:
        print('Error Updating Access Token!!')




#Get Access Token and Store it in AWS Parameter Store
def get_access_token(req_token):
    url = 'https://api.kite.trade/session/token'
    headers = {
    'X-Kite-Version': '3'
    }
    
    h = hashlib.sha256(apiKey.encode("utf-8") + req_token.encode("utf-8") + apiSecret.encode("utf-8"))
    checksum = h.hexdigest()
    
    data = {
        'api_key': apiKey,
        'request_token': req_token,
        'checksum': checksum
    }

    access_response = requests.post(url, headers=headers, data=data)

    if access_response.status_code == 200:
        response_data = access_response.json()
        #print('Response:', response_data)
        access_token = response_data.get('data', {}).get('access_token')
        ssm.put_parameter(Name='/kite/accessToken', Overwrite=True, Value=access_token)
        return 'Success'
    else:
        print('Request failed with status code:', access_response.status_code)
        print('Response:', access_response.text)
        return 'Fail'
