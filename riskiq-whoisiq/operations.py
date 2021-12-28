""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import  base64
import requests

from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('riskiq-whoisiq')


class RiskIQWHOISIQ(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('username')
        self.api_password = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_api_call(self, endpoint=None, method='GET', data=None, params=None):
        try:
            url = self.server_url + endpoint
            b64_credential = base64.b64encode((self.api_key + ":" + self.api_password).encode('utf-8')).decode()
            headers = {'Authorization': "Basic " + b64_credential, 'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, data=data, headers=headers, verify=self.verify_ssl)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_address(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/address'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_domain(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/domain'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_email(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/email'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_name(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/name'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_name_server(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/nameserver'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_org(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/org'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def get_phone(config, params):
    rw = RiskIQWHOISIQ(config)
    endpoint = 'v0/whois/phone'
    param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    response = rw.make_api_call(endpoint=endpoint, params=param_dict)
    return response


def _check_health(config):
    try:
        rw = RiskIQWHOISIQ(config)
        endpoint = 'v0/whois/domain'
        params = {'domain': 'google.com'}
        response = rw.make_api_call(endpoint=endpoint, params=params)
        if response:
            logger.info('connector available')
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_address': get_address,
    'get_domain': get_domain,
    'get_email': get_email,
    'get_name': get_name,
    'get_name_server': get_name_server,
    'get_org': get_org,
    'get_phone': get_phone
}
