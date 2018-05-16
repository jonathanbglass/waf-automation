'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Amazon Software License (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/asl/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import boto3
import math
import time
import json
import datetime
from urllib2 import Request
from urllib2 import urlopen
import os

print('Loading function')
# Constants
API_CALL_NUM_RETRIES = 3
# IP_SET_ID_BAD_BOT = None

IP_SET_ID_BAD_BOT = os.environ['WAFBadBotSet']
# Auxiliary Functions
def waf_update_ip_set(ip_set_id, source_ip):
    waf = boto3.client('waf')
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.update_ip_set(IPSetId=ip_set_id,
                ChangeToken=waf.get_change_token()['ChangeToken'],
                Updates=[{
                    'Action': 'INSERT',
                    'IPSetDescriptor': {
                        'Type': 'IPV4',
                        'Value': "%s/32"%source_ip
                    }
                }]
            )
        except Exception, e:
            delay = math.pow(2, attempt)
            print "[waf_update_ip_set] Retrying in %d seconds..." % (delay)
            time.sleep(delay)
        else:
            break
    else:
        print "[waf_update_ip_set] Failed ALL attempts to call API"

def waf_get_ip_set(ip_set_id):
    response = None
    waf = boto3.client('waf')

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(IPSetId=ip_set_id)
        except Exception, e:
            print(e)
            delay = math.pow(2, attempt)
            print("[waf_get_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[waf_get_ip_set] Failed ALL attempts to call API")

    return response

# Lambda Entry Point


def lambda_handler(event, context):
    response = {}

    print '[lambda_handler] Start'
    try:
        source_ip = event['source_ip'].encode('utf8').split(',')[0].strip()
        bad_bot_ip_set = event['bad_bot_ip_set'].encode('utf8')
        waf_update_ip_set(bad_bot_ip_set, source_ip)
        response['message'] = "[%s] Thanks for the visit."%source_ip

        global IP_SET_ID_BAD_BOT

        if (IP_SET_ID_BAD_BOT == None):
            outputs = {}
            if IP_SET_ID_BAD_BOT == None:
                IP_SET_ID_BAD_BOT = outputs['BadBotSetID']

        print("[lambda_handler] \t\tIP_SET_ID_BAD_BOT = %s"%IP_SET_ID_BAD_BOT)

    except Exception as e:
        print e
    print '[lambda_handler] End'

    return response
