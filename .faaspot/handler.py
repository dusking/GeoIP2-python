import os
import json
import urlparse

import geoip2.webservice


def geoip(event, context):
    """get geo-info for given ip"""
    query_params = event.get("query", {})
    request_ip = query_params.get('ip')
    print ("context: {0}".format(context))
    user_id = context.get_doc('user_id')
    license_key = context.get_doc('key')
    if not user_id or not license_key:
        print ("missing data.. user_id: {}, license_key: {}".format(user_id, license_key))
    print ("going to extract ip info for: {0}".format(request_ip))
    client = geoip2.webservice.Client(user_id, license_key)
    response = client.insights(request_ip)
    response = 'Geo: {0} {1}, TZ: {2}, Organization: {3} ({4})'\
        .format(response.country.name, response.city.name, response.location.time_zone,
                response.traits.organization, response.traits.user_type)
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
