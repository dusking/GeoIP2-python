import os
import json
import urlparse
import requests
import ipaddress
import threading

import geoip2.database

import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES


def unpad(data):
    return data[0:-ord(data[-1])]


def decrypt(hex_data):
    key = 'WmFKzhC3YRmEU4dPY3hza8HUu7653Gg3'
    iv = 'ZS9ATh5Wz4jUN895'
    data = ''.join(map(chr, bytearray.fromhex(hex_data)))
    aes = AES.new(key, AES.MODE_CBC, iv)
    data = unpad(aes.decrypt(data))
    return base64.b64decode(data)


def geoip(args):
    """get geo-info for given ip"""
    ip_addr = args['ip_addr'].strip("\"")
    raw = args.get('raw', False)
    print("retrieving geo locatiopn info for: {}".format(ip_addr))
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')    
    geo_ip_info = reader.city(ip_addr)
    if raw:
        response = geo_ip_info.raw
    else:
        country = geo_ip_info.country.name
        city = geo_ip_info.city.name
        continent = geo_ip_info.continent.name
        subdivision = geo_ip_info.subdivisions.most_specific.name
        timezone = geo_ip_info.location.time_zone
        latitude = geo_ip_info.location.latitude
        longitude = geo_ip_info.location.longitude
        if subdivision != city:
            location = '{}, {}, {}'.format(city, subdivision, country)
        else:
            location = '{}, {}'.format(city, subdivision)
        response = {'country': country, 'city': city, 'location': location, 'subdivision': subdivision,
                'continent': continent, 'timezone': timezone, 'latitude': latitude, 'longitude': longitude}
    print("location: {}".format(response))
    reader.close()
    return response


def validate_input(token, ip_addr):
    user_data = ''
    if not token:
        return "missing user token"
    try:
        user_data = decrypt(token.replace('Basic ', ''))
        print ("user_data: {0}".format(user_data))
    except ValueError:
        return {'error': '`{}` does not appear to be a valid token'.format(token)}
    if not ip_addr:
        return {'error': 'missing ip_addr'}
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        return {'error': '`{}` does not appear to be a valid ip address'.format(ip_addr)}
    return {'user_data': user_data}


def callPost(body):    
    print ('going to send request.. body: {}'.format(body))
    headers = {"Content-Type":"application/json", "Token":"Basic 62646018047677d2f204ffae7dac388bc4cb227d963b729d"}    
    send_message_url = 'https://us-central1-faaspotit.cloudfunctions.net/google-bigquery'
    requests.post(send_message_url, data=json.dumps(body), headers=headers)


def update_usage(user_id, user_ip_addr, function_id, function_name):
    body = {"user_id": user_id, 'source_ip': user_ip_addr, 'function_id': function_id, 'function_name': function_name}
    th = threading.Thread(target=callPost, args=[body])
    th.daemon = True
    th.start()


def geoip_wrapper(event, context):
    print ("event: {0}".format(event))
    print ("context: {0}".format(context))
    body = event.get("body", "{}")
    try:
        body = json.loads(body)
    except ValueError:
        body = urlparse.parse_qs(body)  
        body = {k: v[0] for k, v in body.iteritems()}
    headers = event.get("headers", {})        
    token = headers.get('Token')    
    user_ip = headers.get('X-Forwarded-For')
    ip_addr = body.get('ip_addr', "").strip("\"")  

    result = validate_input(token, ip_addr)
    err = result.get('error')
    if err:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': err}),
            'headers': {"Content-Type": "application/json"}
        }
    user_data = result.get('user_data')
    user_id = user_data.split(':')[0]
    function_name = event.get('uri').split('/')[-1]
    function_id = context.get('functionId')
    update_usage(user_id, user_ip, function_id, function_name)
    
    response = json.dumps(geoip({'ip_addr': ip_addr, 'raw': False}))    
    return {
        'statusCode': 200,
        'body': response,
        'headers': {"Content-Type": "application/json"}
    }


def geoipraw_wrapper(event, context):
    print ("event: {0}".format(event))
    print ("context: {0}".format(context))
    body = event.get("body", "{}")
    try:
        body = json.loads(body)
    except ValueError:
        body = urlparse.parse_qs(body)  
        body = {k: v[0] for k, v in body.iteritems()}
    headers = event.get("headers", {})        
    token = headers.get('Token')    
    user_ip = headers.get('X-Forwarded-For')
    ip_addr = body.get('ip_addr', "").strip("\"")  

    result = validate_input(token, ip_addr)
    err = result.get('error')
    if err:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': err}),
            'headers': {"Content-Type": "application/json"}
        }
    user_data = result.get('user_data')
    user_id = user_data.split(':')[0]
    function_name = event.get('uri').split('/')[-1]
    function_id = context.get('functionId')
    update_usage(user_id, user_ip, function_id, function_name)

    response = json.dumps(geoip({'ip_addr': ip_addr, 'raw': True}))    
    return {
        'statusCode': 200,
        'body': response,
        'headers': {"Content-Type": "application/json"}
    }



def slackcommand(event, context):
    body = event.get("body", "{}")
    # Slack sends all the data in the body, but as query param string (k=v&kk=vv..)
    slack_event = urlparse.parse_qs(body)
    print (slack_event)
    text = slack_event.get('text')
    text = text[0] if text else None
    if not text or text == 'help':
        return _slack_response('Need to supply IP address', visible_all=False)
    user_id = os.environ.get('user_id')
    license_key = os.environ.get('key')
    client = geoip2.webservice.Client(user_id, license_key)
    response = client.insights(text)
    response = '*_{0} Info_* \n*Location*: {1} {2} \n*TZ*: {3} \n*Organization*: {4} ({5})' \
        .format(text, response.country.name, response.city.name, response.location.time_zone,
                response.traits.organization, response.traits.user_type)
    return _slack_response(response)


def _slack_response(text, visible_all=True):
    response_type = 'in_channel' if visible_all else 'ephemeral'
    response = {
        "response_type": response_type,
        "text": text,
        "mrkdwn": True
    }
    return {
        'statusCode': 200,
        'body': json.dumps(response),
        'headers': {"Content-Type": "application/json"}
    }
