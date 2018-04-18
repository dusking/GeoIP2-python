import os
import json
import urlparse
import ipaddress

import geoip2.database
# import geoip2.webservice

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
    if not token:
        return "missing user token"
    try:
        user_data = decrypt(token.replace('Basic ', ''))
        print ("user_data: {0}".format(user_data))
    except ValueError:
        return '`{}` does not appear to be a valid token'.format(token)
    if not ip_addr:
        return 'missing ip_addr'
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        return '`{}` does not appear to be a valid ip address'.format(ip_addr)
    return None


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
    user_ip = headers.get('X-Forwarded-For')
    token = headers.get('Token')    
    print ("user_ip: {0}".format(user_ip))
    
    ip_addr = body.get('ip_addr', "").strip("\"")  
    err = validate_input(token, ip_addr)
    if err:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': err}),
            'headers': {"Content-Type": "application/json"}
        }
    
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
    user_ip = headers.get('X-Forwarded-For')
    token = headers.get('Token')    
    print ("user_ip: {0}".format(user_ip))

    ip_addr = body.get('ip_addr', "").strip("\"")  
    err = validate_input(token, ip_addr)
    if err:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': err}),
            'headers': {"Content-Type": "application/json"}
        }

    response = json.dumps(geoip({'ip_addr': ip_addr, 'raw': True}))    
    return {
        'statusCode': 200,
        'body': response,
        'headers': {"Content-Type": "application/json"}
    }


# def geoip_service(event, context):
#     """get geo-info for given ip"""
#     query_params = event.get("query", {})
#     request_ip = query_params.get('ip')
#     print ("context: {0}".format(context))
#     user_id = context.get_doc('user_id')
#     license_key = context.get_doc('key')
#     if not user_id or not license_key:
#         print ("missing data.. user_id: {}, license_key: {}".format(user_id, license_key))
#     print ("going to extract ip info for: {0}".format(request_ip))
#     client = geoip2.webservice.Client(user_id, license_key)
#     response = client.insights(request_ip)
#     response = 'Geo: {0} {1}, TZ: {2}, Organization: {3} ({4})'\
#         .format(response.country.name, response.city.name, response.location.time_zone,
#                 response.traits.organization, response.traits.user_type)
#     return {
#         'statusCode': 200,
#         'body': response,
#         'headers': {"Content-Type": "application/json"}
#     }


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
