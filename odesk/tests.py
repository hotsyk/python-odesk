# -*- coding: utf-8 -*-

# Python bindings to oDesk API
# python-odesk version 0.5
# (C) 2010-2014 oDesk

from decimal import Decimal


from odesk import Client
from odesk import utils
from odesk.exceptions import (HTTP400BadRequestError,
                              HTTP401UnauthorizedError,
                              HTTP403ForbiddenError,
                              HTTP404NotFoundError,
                              ApiValueError,
                              IncorrectJsonResponseError)

from odesk.namespaces import Namespace
from odesk.oauth import OAuth
from odesk.routers.team import Team, Team_V2
from odesk.http import ODESK_ERROR_CODE, ODESK_ERROR_MESSAGE

from nose.tools import eq_, ok_
from mock import Mock, patch
from six.moves import urllib
from six.moves import http_client

try:
    import json
except ImportError:
    import simplejson as json


class MicroMock(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


sample_json_dict = {'glossary':
                    {'GlossDiv':
                     {'GlossList':
                      {'GlossEntry':
                       {'GlossDef':
                        {'GlossSeeAlso': ['GML', 'XML'],
                         'para': 'A meta-markup language'},
                         'GlossSee': 'markup',
                         'Acronym': 'SGML',
                         'GlossTerm': 'Standard Generalized Markup Language',
                         'Abbrev': 'ISO 8879:1986',
                         'SortAs': 'SGML',
                         'ID': 'SGML'}},
                         'title': 'S'},
                         'title': 'example glossary'}}


def patched_urlopen(*args, **kwargs):
    return MicroMock(data=json.dumps(sample_json_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen)
def test_client_urlopen():
    public_key = 'public'
    secret_key = 'secret'

    client = Client(public_key, secret_key,
                    oauth_access_token='some access token',
                    oauth_access_token_secret='some access token secret')

    #test urlopen
    data = [{'url': 'http://test.url',
             'data': {'foo': 'bar'},
             'method': 'GET',
             'result_data': None,
             'result_url': 'http://test.url?api_sig=ddbf4b10a47ca8300554441dc'
             '7c9042b&api_key=public&foo=bar',
             'result_method': 'GET'},
            {'url': 'http://test.url',
             'data': {},
             'method': 'POST',
             'result_data': 'api_sig=ba343f176db8166c4b7e88911e7e'
             '46ec&api_key=public',
             'result_url': 'http://test.url',
             'result_method': 'POST'},
            {'url': 'http://test.url',
             'data': {},
             'method': 'PUT',
             'result_data': 'api_sig=52cbaea073a5d47abdffc7fc8ccd839b&'
             'api_key=public&http_method=put',
             'result_url': 'http://test.url',
             'result_method': 'POST'},
            {'url': 'http://test.url',
             'data': {},
             'method': 'DELETE',
             'result_data': 'api_sig=8621f072b1492fbd164d808307ba72b9&'
             'api_key=public&http_method=delete',
             'result_url': 'http://test.url',
             'result_method': 'POST'},
            ]

    result_json = json.dumps(sample_json_dict)

    for params in data:
        result = client.urlopen(url=params['url'],
                                data=params['data'],
                                method=params['method'])
        assert result.data == result_json, (result.data, result_json)


def patched_urlopen_error(method, url, code=http_client.BAD_REQUEST,
                          message=None, data=None, **kwargs):
    getheaders = Mock()
    getheaders.return_value = {ODESK_ERROR_CODE: code,
                               ODESK_ERROR_MESSAGE: message}
    return MicroMock(data=data, getheaders=getheaders, status=code)


def patched_urlopen_incorrect_json(self, method, url, **kwargs):
    return patched_urlopen_error(method, url, code=http_client.OK,
                                 data='Service temporarily unavailable')


def patched_urlopen_400(self, method, url, **kwargs):
    return patched_urlopen_error(
        method, url, code=http_client.BAD_REQUEST,
        message='Limit exceeded', **kwargs)


def patched_urlopen_401(self, method, url, **kwargs):
    return patched_urlopen_error(
        method, url, code=http_client.UNAUTHORIZED,
        message='Not authorized', **kwargs)


def patched_urlopen_403(self, method, url, **kwargs):
    return patched_urlopen_error(
        method, url, code=http_client.FORBIDDEN,
        message='Forbidden', **kwargs)


def patched_urlopen_404(self, method, url, **kwargs):
    return patched_urlopen_error(
        method, url, code=http_client.NOT_FOUND,
        message='Not found', **kwargs)


def patched_urlopen_500(self, method, url, **kwargs):
    return patched_urlopen_error(
        method, url, code=http_client.INTERNAL_SERVER_ERROR,
        message='Internal server error', **kwargs)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_incorrect_json)
def client_read_incorrect_json(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_400)
def client_read_400(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_401)
def client_read_401(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_403)
def client_read_403(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_404)
def client_read_404(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_500)
def client_read_500(client, url):
    return client.read(url)


@patch('urllib3.PoolManager.urlopen', patched_urlopen)
def test_client_read():
    """Test client read() method.

    Test cases:
      method default (get) - other we already tested

      format json|yaml ( should produce error)

      codes 200|400|401|403|404|500

    """
    public_key = 'public'
    secret_key = 'secret'

    client = Client(public_key, secret_key,
                    oauth_access_token='some access token',
                    oauth_access_token_secret='some access token secret')
    test_url = 'http://test.url'

    # Produce error on format other then json
    class NotJsonException(Exception):
        pass

    try:
        client.read(url=test_url, format='yaml')
        raise NotJsonException("Client.read() doesn't produce error on "
                               "yaml format")
    except NotJsonException:
        raise
    except Exception:
        pass

    # Test get, all ok
    result = client.read(url=test_url)
    assert result == sample_json_dict, result

    # Test get and status is ok, but json is incorrect,
    # IncorrectJsonResponseError should be raised
    try:
        result = client_read_incorrect_json(client=client, url=test_url)
        ok_(0, "No exception raised for 200 code and "
               "incorrect json response: {0}".format(result))
    except IncorrectJsonResponseError:
        pass
    except Exception as e:
        assert 0, "Incorrect exception raised for 200 code " \
            "and incorrect json response: " + str(e)

    # Test get, 400 error
    try:
        result = client_read_400(client=client, url=test_url)
    except HTTP400BadRequestError:
        pass
    except Exception as e:
        raise
        assert 0, "Incorrect exception raised for 400 code: " + str(e)

    # Test get, 401 error
    try:
        result = client_read_401(client=client, url=test_url)
    except HTTP401UnauthorizedError:
        pass
    except Exception as e:
        assert 0, "Incorrect exception raised for 401 code: " + str(e)

    # Test get, 403 error
    try:
        result = client_read_403(client=client, url=test_url)
    except HTTP403ForbiddenError:
        pass
    except Exception as e:
        assert 0, "Incorrect exception raised for 403 code: " + str(e)

    # Test get, 404 error
    try:
        result = client_read_404(client=client, url=test_url)
    except HTTP404NotFoundError:
        pass
    except Exception as e:
        assert 0, "Incorrect exception raised for 404 code: " + str(e)

    # Test get, 500 error
    try:
        result = client_read_500(client=client, url=test_url)
    except urllib.error.HTTPError as e:
        if e.code == http_client.INTERNAL_SERVER_ERROR:
            pass
        else:
            assert 0, "Incorrect exception raised for 500 code: " + str(e)
    except Exception as e:
        assert 0, "Incorrect exception raised for 500 code: " + str(e)


def get_client():
    public_key = 'public'
    secret_key = 'secret'
    oauth_access_token = 'some token'
    oauth_access_token_secret = 'some token secret'
    return Client(public_key, secret_key,
                  oauth_access_token,
                  oauth_access_token_secret)


@patch('urllib3.PoolManager.urlopen', patched_urlopen)
def test_client():
    c = get_client()
    test_url = "http://test.url"

    result = c.get(test_url)
    assert result == sample_json_dict, result

    result = c.post(test_url)
    assert result == sample_json_dict, result

    result = c.put(test_url)
    assert result == sample_json_dict, result

    result = c.delete(test_url)
    assert result == sample_json_dict, result


@patch('urllib3.PoolManager.urlopen', patched_urlopen)
def test_namespace():
    ns = Namespace(get_client())
    test_url = "http://test.url"

    #test full_url
    full_url = ns.full_url('test')
    assert full_url == 'https://www.odesk.com/api/Nonev1/test', full_url

    result = ns.get(test_url)
    assert result == sample_json_dict, result

    result = ns.post(test_url)
    assert result == sample_json_dict, result

    result = ns.put(test_url)
    assert result == sample_json_dict, result

    result = ns.delete(test_url)
    assert result == sample_json_dict, result


teamrooms_dict = {'teamrooms':
                  {'teamroom':
                   {'team_ref': '1',
                    'name': 'oDesk',
                    'recno': '1',
                    'parent_team_ref': '1',
                    'company_name': 'oDesk',
                    'company_recno': '1',
                    'teamroom_api': '/api/team/v1/teamrooms/odesk:some.json',
                    'id': 'odesk:some'}},
                  'teamroom': {'snapshot': 'test snapshot'},
                  'snapshots': {'user': 'test', 'snapshot': 'test'},
                  'snapshot': {'status': 'private'}
                  }


def patched_urlopen_teamrooms(*args, **kwargs):
    return MicroMock(data=json.dumps(teamrooms_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_teamrooms)
def test_team():
    te = Team(get_client())
    te_v2 = Team_V2(get_client())

    #test full_url
    full_url = te.full_url('test')
    assert full_url == 'https://www.odesk.com/api/team/v1/test', full_url

    #test get_teamrooms
    assert te_v2.get_teamrooms() == \
        [teamrooms_dict['teamrooms']['teamroom']], te.get_teamrooms()

    #test get_snapshots
    assert te_v2.get_snapshots(1) == \
        [teamrooms_dict['teamroom']['snapshot']], te.get_snapshots(1)

    #test get_snapshot
    assert te.get_snapshot(1, 1) == teamrooms_dict['snapshot'], \
        te.get_snapshot(1, 1)

    #test update_snapshot
    assert te.update_snapshot(1, 1, memo='memo') == teamrooms_dict, \
        te.update_snapshot(1, 1, memo='memo')

    #test update_snapshot
    assert te.delete_snapshot(1, 1) == teamrooms_dict, te.delete_snapshot(1, 1)

    #test get_workdiaries
    eq_(te.get_workdiaries(1, 1, 1), (teamrooms_dict['snapshots']['user'],
        [teamrooms_dict['snapshots']['snapshot']]))


teamrooms_dict_none = {'teamrooms': '',
                       'teamroom': '',
                       'snapshots': '',
                       'snapshot': ''
                       }


def patched_urlopen_teamrooms_none(*args, **kwargs):
    return MicroMock(data=json.dumps(teamrooms_dict_none), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_teamrooms_none)
def test_teamrooms_none():
    te = Team(get_client())
    te_v2 = Team_V2(get_client())

    #test full_url
    full_url = te.full_url('test')
    assert full_url == 'https://www.odesk.com/api/team/v1/test', full_url

    #test get_teamrooms
    assert te_v2.get_teamrooms() == [], te_v2.get_teamrooms()

    #test get_snapshots
    assert te_v2.get_snapshots(1) == [], te_v2.get_snapshots(1)

    #test get_snapshot
    eq_(te.get_snapshot(1, 1), teamrooms_dict_none['snapshot'])


userroles = {'userrole':
             [{'parent_team__reference': '1',
              'user__id': 'testuser', 'team__id': 'test:t',
              'reference': '1', 'team__name': 'te',
              'company__reference': '1',
              'user__reference': '1',
              'user__first_name': 'Test',
              'user__last_name': 'Development',
              'parent_team__id': 'testdev',
              'team__reference': '1', 'role': 'manager',
              'affiliation_status': 'none', 'engagement__reference': '',
              'parent_team__name': 'TestDev', 'has_team_room_access': '1',
              'company__name': 'Test Dev',
              'permissions':
              {'permission': ['manage_employment', 'manage_recruiting']}}]}

engagement = {'status': 'active',
              'buyer_team__reference': '1', 'provider__reference': '2',
              'job__title': 'development', 'roles': {'role': 'buyer'},
              'reference': '1', 'engagement_end_date': '',
              'fixed_price_upfront_payment': '0',
              'fixed_pay_amount_agreed': '1.00',
              'provider__id': 'test_provider',
              'buyer_team__id': 'testteam:aa',
              'engagement_job_type': 'fixed-price',
              'job__reference': '1', 'provider_team__reference': '',
              'engagement_title': 'Developer',
              'fixed_charge_amount_agreed': '0.01',
              'created_time': '0000', 'provider_team__id': '',
              'offer__reference': '',
              'engagement_start_date': '000', 'description': ''}

engagements = {'lister':
               {'total_items': '10', 'query': '',
                'paging': {'count': '10', 'offset': '0'}, 'sort': ''},
               'engagement': [engagement, engagement],
               }

offer = {'provider__reference': '1',
         'signed_by_buyer_user': '',
         'reference': '1', 'job__description': 'python',
         'buyer_company__name': 'Python community',
         'engagement_title': 'developer', 'created_time': '000',
         'buyer_company__reference': '2', 'buyer_team__id': 'testteam:aa',
         'interview_status': 'in_process', 'buyer_team__reference': '1',
         'signed_time_buyer': '', 'has_buyer_signed': '',
         'signed_time_provider': '', 'created_by': 'testuser',
         'job__reference': '2', 'engagement_start_date': '00000',
         'fixed_charge_amount_agreed': '0.01', 'provider_team__id': '',
         'status': '', 'signed_by_provider_user': '',
         'engagement_job_type': 'fixed-price', 'description': '',
         'provider_team__name': '', 'fixed_pay_amount_agreed': '0.01',
         'candidacy_status': 'active', 'has_provider_signed': '',
         'message_from_provider': '', 'my_role': 'buyer',
         'key': '~~0001', 'message_from_buyer': '',
         'buyer_team__name': 'Python community 2',
         'engagement_end_date': '', 'fixed_price_upfront_payment': '0',
         'created_type': 'buyer', 'provider_team__reference': '',
         'job__title': 'translation', 'expiration_date': '',
         'engagement__reference': ''}

offers = {'lister':
          {'total_items': '10', 'query': '', 'paging':
           {'count': '10', 'offset': '0'}, 'sort': ''},
          'offer': [offer, offer]}

job = {'subcategory': 'Development', 'reference': '1',
       'buyer_company__name': 'Python community',
       'job_type': 'fixed-price', 'created_time': '000',
       'created_by': 'test', 'duration': '',
       'last_candidacy_access_time': '',
       'category': 'Web',
       'buyer_team__reference': '169108', 'title': 'translation',
       'buyer_company__reference': '1', 'num_active_candidates': '0',
       'buyer_team__name': 'Python community 2', 'start_date': '000',
       'status': 'filled', 'num_new_candidates': '0',
       'description': 'test', 'end_date': '000',
       'public_url': 'http://www.odesk.com/jobs/~~0001',
       'visibility': 'invite-only', 'buyer_team__id': 'testteam:aa',
       'num_candidates': '1', 'budget': '1000', 'cancelled_date': '',
       'filled_date': '0000'}

jobs = [job, job]

task = {'reference': 'test', 'company_reference': '1',
        'team__reference': '1', 'user__reference': '1',
        'code': '1', 'description': 'test task',
        'url': 'http://url.odesk.com/task', 'level': '1'}

tasks = [task, task]

auth_user = {'first_name': 'TestF', 'last_name': 'TestL',
             'uid': 'testuser', 'timezone_offset': '0',
             'timezone': 'Europe/Athens', 'mail': 'test_user@odesk.com',
             'messenger_id': '', 'messenger_type': 'yahoo'}

user = {'status': 'active', 'first_name': 'TestF',
        'last_name': 'TestL', 'reference': '0001',
        'timezone_offset': '10800',
        'public_url': 'http://www.odesk.com/users/~~000',
        'is_provider': '1',
        'timezone': 'GMT+02:00 Athens, Helsinki, Istanbul',
        'id': 'testuser'}

team = {'status': 'active', 'parent_team__reference': '0',
        'name': 'Test',
        'reference': '1',
        'company__reference': '1',
        'id': 'test',
        'parent_team__id': 'test_parent',
        'company_name': 'Test', 'is_hidden': '',
        'parent_team__name': 'Test parent'}

company = {'status': 'active',
           'name': 'Test',
           'reference': '1',
           'company_id': '1',
           'owner_user_id': '1', }

hr_dict = {'auth_user': auth_user,
           'server_time': '0000',
           'user': user,
           'team': team,
           'company': company,
           'teams': [team, team],
           'companies': [company, company],
           'users': [user, user],
           'tasks': task,
           'userroles': userroles,
           'engagements': engagements,
           'engagement': engagement,
           'offer': offer,
           'offers': offers,
           'job': job,
           'jobs': jobs}


def patched_urlopen_hr(*args, **kwargs):
    return MicroMock(data=json.dumps(hr_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_user():
    hr = get_client().hr

    #test get_user
    assert hr.get_user(1) == hr_dict['user'], hr.get_user(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_companies():
    hr = get_client().hr
    #test get_companies
    assert hr.get_companies() == hr_dict['companies'], hr.get_companies()

    #test get_company
    assert hr.get_company(1) == hr_dict['company'], hr.get_company(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_company_teams():
    hr = get_client().hr
    #test get_company_teams
    assert hr.get_company_teams(1) == hr_dict['teams'], hr.get_company_teams(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_company_users():
    hr = get_client().hr
    #test get_company_users
    assert hr.get_company_users(1) == hr_dict['users'], hr.get_company_users(1)
    assert hr.get_company_users(1, False) == hr_dict['users'], \
        hr.get_company_users(1, False)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_teams():
    hr = get_client().hr
    #test get_teams
    assert hr.get_teams() == hr_dict['teams'], hr.get_teams()

    #test get_team
    assert hr.get_team(1) == hr_dict['team'], hr.get_team(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_team_users():
    hr = get_client().hr
    #test get_team_users
    assert hr.get_team_users(1) == hr_dict['users'], hr.get_team_users(1)
    assert hr.get_team_users(1, False) == hr_dict['users'], \
        hr.get_team_users(1, False)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_userroles():
    hr = get_client().hr
    #test get_user_roles
    assert hr.get_user_roles() == hr_dict['userroles'], hr.get_user_role()


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_jobs():
    hr = get_client().hr
    #test get_jobs
    assert hr.get_jobs(1) == hr_dict['jobs'], hr.get_jobs()
    assert hr.get_job(1) == hr_dict['job'], hr.get_job(1)
    result = hr.update_job(1, 2, 'title', 'desc', 'public', budget=100,
                           status='open')
    eq_(result, hr_dict)
    assert hr.delete_job(1, 41) == hr_dict, hr.delete_job(1, 41)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_offers():
    hr = get_client().hr
    #test get_offers
    assert hr.get_offers(1) == hr_dict['offers'], hr.get_offers()
    assert hr.get_offer(1) == hr_dict['offer'], hr.get_offer(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hr)
def test_get_hrv2_engagements():
    hr = get_client().hr

    eq_(hr.get_engagements(), hr_dict['engagements'])

    eq_(hr.get_engagements(provider_reference=1), hr_dict['engagements'])
    eq_(hr.get_engagements(profile_key=1), hr_dict['engagements'])
    eq_(hr.get_engagement(1), hr_dict['engagement'])


adjustments = {'adjustment': {'reference': '100'}}


def patched_urlopen_hradjustment(*args, **kwargs):
    return MicroMock(data=json.dumps(adjustments), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_hradjustment)
def test_hrv2_post_adjustment():
    hr = get_client().hr

    # Using ``amount``
    result = hr.post_team_adjustment(
        1, 2, 'a test', amount=100, notes='test note')
    assert result == adjustments['adjustment'], result

    # Using ``charge_amount``
    result = hr.post_team_adjustment(
        1, 2, 'a test', charge_amount=100, notes='test note')
    assert result == adjustments['adjustment'], result

    try:
        # Using ``amount`` and ``charge_amount`` will raise error
        hr.post_team_adjustment(
            1, 2, 'a test', amount=100, charge_amount=110, notes='test note')
        raise Exception('No error ApiValueError was raised when using'
                        'both ``amount`` and ``charge_amount``')
    except ApiValueError:
        pass

    try:
        # If both ``amount`` and ``charge_amount`` are absent,
        # error should be raised
        hr.post_team_adjustment(1, 2, 'a test', notes='test note')
        raise Exception('No error ApiValueError was raised when both'
                        'both ``amount`` and ``charge_amount`` are absent')
    except ApiValueError:
        pass

job_data = {
    'buyer_team_reference': 111,
    'title': 'Test job from API',
    'job_type': 'hourly',
    'description': 'this is test job, please do not apply to it',
    'visibility': 'odesk',
    'category': 'Web Development',
    'subcategory': 'Other - Web Development',
    'budget': 100,
    'duration': 10,
    'start_date': 'some start date',
    'end_date': 'some end date',
    'skills': ['Python', 'JS']
}


def patched_urlopen_job_data_parameters(self, method, url, **kwargs):
    post_dict = urllib.parse.parse_qs(kwargs.get('body'))
    post_dict.pop('oauth_timestamp')
    post_dict.pop('oauth_signature')
    post_dict.pop('oauth_nonce')
    eq_(
        dict(post_dict.items()),
        {'category': ['Web Development'], 'buyer_team__reference': ['111'],
         'subcategory': ['Other - Web Development'],
         'end_date': ['some end date'], 'title': ['Test job from API'],
         'skills': ['Python;JS'], 'job_type': ['hourly'],
         'oauth_consumer_key': ['public'],
         'oauth_signature_method': ['HMAC-SHA1'], 'budget': ['100'],
         'visibility': ['odesk'],
         'oauth_version': ['1.0'], 'oauth_token': ['some token'],
         'oauth_body_hash': ['2jmj7l5rSw0yVb/vlWAYkK/YBwk='],
         'duration': ['10'],
         'start_date': ['some start date'],
         'description': ['this is test job, please do not apply to it']})
    return MicroMock(data='{"some":"data"}', status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_job_data_parameters)
def test_job_data_parameters():
    hr = get_client().hr
    hr.post_job(**job_data)


provider_dict = {'profile':
                 {'response_time': '31.0000000000000000',
                  'dev_agency_ref': '',
                  'dev_adj_score_recent': '0',
                  'dev_ui_profile_access': 'Public',
                  'dev_portrait': '',
                  'dev_ic': 'Freelance Provider',
                  'certification': '',
                  'dev_usr_score': '0',
                  'dev_country': 'Ukraine',
                  'dev_recent_rank_percentile': '0',
                  'dev_profile_title': 'Python developer',
                  'dev_groups': '',
                  'dev_scores':
                  {'dev_score': [
                      {'description':
                       'competency and skills for the job, understanding of '
                       'specifications/instructions',
                       'avg_category_score_recent': '',
                       'avg_category_score': '',
                       'order': '1', 'label': 'Skills'},
                      {'description': 'quality of work deliverables',
                       'avg_category_score_recent': '',
                       'avg_category_score': '', 'order': '2',
                       'label': 'Quality'},
                      ]
                   }},
                   'providers': {'test': 'test'},
                   'jobs': {'test': 'test'},
                   'otherexp': 'experiences',
                   'skills': 'skills',
                   'tests': 'tests',
                   'certificates': 'certificates',
                   'employments': 'employments',
                   'educations': 'employments',
                   'projects': 'projects',
                   'quick_info': 'quick_info',
                   'categories': 'category 1',
                   'regions': 'region 1',
                   'tests': 'test 1'}


def patched_urlopen_provider(*args, **kwargs):
    return MicroMock(data=json.dumps(provider_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_provider)
def test_provider():
    pr = get_client().provider

    #test full_url
    full_url = pr.full_url('test')
    assert full_url == 'https://www.odesk.com/api/profiles/v1/test', full_url

    #test get_provider
    assert pr.get_provider(1) == provider_dict['profile'], pr.get_provider(1)

    #test get_provider_brief
    assert pr.get_provider_brief(1) == provider_dict['profile'], \
        pr.get_provider_brief(1)

    #test search_providers
    assert pr.search_providers(data={'a': 1}) == provider_dict['providers'], \
        pr.search_providers(data={'a': 1})

    #test search_jobs
    assert pr.search_jobs(data={'a': 1}) == provider_dict['jobs'], \
        pr.get_jobs(data={'a': 1})

    result = pr.get_categories_metadata()
    assert result == provider_dict['categories']

    result = pr.get_skills_metadata()
    assert result == provider_dict['skills']

    result = pr.get_regions_metadata()
    assert result == provider_dict['regions']

    result = pr.get_tests_metadata()
    assert result == provider_dict['tests']


trays_dict = {'trays': [{'unread': '0',
              'type': 'sent',
              'id': '1',
              'tray_api': '/api/mc/v1/trays/username/sent.json'},
              {'unread': '0',
               'type': 'inbox',
               'id': '2',
               'tray_api': '/api/mc/v1/trays/username/inbox.json'},
              {'unread': '0',
               'type': 'notifications',
               'id': '3',
               'tray_api': '/api/mc/v1/trays/username/notifications.json'}]}


def patched_urlopen_trays(*args, **kwargs):
    return MicroMock(data=json.dumps(trays_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_trays)
def test_get_trays():
    mc = get_client().mc

    #test full_url
    full_url = mc.full_url('test')
    assert full_url == 'https://www.odesk.com/api/mc/v1/test', full_url

    #test get_trays
    assert mc.get_trays(1) == trays_dict['trays'], mc.get_trays(1)
    assert mc.get_trays(1, paging_offset=10, paging_count=10) ==\
        trays_dict['trays'], mc.get_trays(1, paging_offset=10, paging_count=10)


tray_content_dict = {"current_tray": {"threads": '1'}}


def patched_urlopen_tray_content(*args, **kwargs):
    return MicroMock(data=json.dumps(tray_content_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_tray_content)
def test_get_tray_content():
    mc = get_client().mc

    #test get_tray_content
    assert mc.get_tray_content(1, 1) ==\
        tray_content_dict['current_tray']['threads'], mc.get_tray_content(1, 1)
    assert mc.get_tray_content(1, 1, paging_offset=10, paging_count=10) ==\
        tray_content_dict['current_tray']['threads'], \
        mc.get_tray_content(1, 1, paging_offset=10, paging_count=10)


thread_content_dict = {"thread": {"test": '1'}}


def patched_urlopen_thread_content(*args, **kwargs):
    return MicroMock(data=json.dumps(thread_content_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_thread_content)
def test_get_thread_content():
    mc = get_client().mc

    #test get_provider
    assert mc.get_thread_content(1, 1) ==\
         thread_content_dict['thread'], mc.get_thread_content(1, 1)
    assert mc.get_thread_content(1, 1, paging_offset=10, paging_count=10) ==\
         thread_content_dict['thread'], \
         mc.get_thread_content(1, 1, paging_offset=10, paging_count=10)


read_thread_content_dict = {"thread": {"test": '1'}}


def patched_urlopen_read_thread_content(*args, **kwargs):
    return MicroMock(data=json.dumps(read_thread_content_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_read_thread_content)
def test_put_threads_read_unread():
    mc = get_client().mc

    read = mc.put_threads_read('test', [1, 2, 3])
    assert read == read_thread_content_dict, read

    unread = mc.put_threads_read('test', [5, 6, 7])
    assert unread == read_thread_content_dict, unread

    read = mc.put_threads_unread('test', [1, 2, 3])
    assert read == read_thread_content_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_read_thread_content)
def test_put_threads_starred_unstarred():
    mc = get_client().mc

    starred = mc.put_threads_starred('test', [1, 2, 3])
    assert starred == read_thread_content_dict, starred

    unstarred = mc.put_threads_unstarred('test', [5, 6, 7])
    assert unstarred == read_thread_content_dict, unstarred


@patch('urllib3.PoolManager.urlopen', patched_urlopen_read_thread_content)
def test_put_threads_deleted_undeleted():
    mc = get_client().mc

    deleted = mc.put_threads_deleted('test', [1, 2, 3])
    assert deleted == read_thread_content_dict, deleted

    undeleted = mc.put_threads_undeleted('test', [5, 6, 7])
    assert undeleted == read_thread_content_dict, undeleted


@patch('urllib3.PoolManager.urlopen', patched_urlopen_read_thread_content)
def test_post_message():
    mc = get_client().mc

    message = mc.post_message('username', 'recepient1,recepient2', 'subject',
                              'body')
    assert message == read_thread_content_dict, message

    message = mc.post_message('username', ('recepient1@sss',\
        'recepient`іваівsss'), 'subject',
                              'body')
    assert message == read_thread_content_dict, message

    message = mc.post_message('username',\
        'recepient1@sss,1%&&|-!@#recepient`іваівsss', 'subject',
                              'body')
    assert message == read_thread_content_dict, message

    reply = mc.post_message('username', 'recepient1,recepient2', 'subject',
                              'body', 123)
    assert reply == read_thread_content_dict, reply


timereport_dict = {'table':
     {'rows':
      [{'c':
        [{'v': '20100513'},
         {'v': 'company1:team1'},
         {'v': '1'},
         {'v': '1'},
         {'v': '0'},
         {'v': '1'},
         {'v': 'Bug 1: Test'}]}],
         'cols':
         [{'type': 'date', 'label': 'worked_on'},
          {'type': 'string', 'label': 'assignment_team_id'},
          {'type': 'number', 'label': 'hours'},
          {'type': 'number', 'label': 'earnings'},
          {'type': 'number', 'label': 'earnings_offline'},
          {'type': 'string', 'label': 'task'},
          {'type': 'string', 'label': 'memo'}]}}


def patched_urlopen_timereport_content(*args, **kwargs):
    return MicroMock(data=json.dumps(timereport_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_timereport_content)
def test_get_provider_timereport():
    tc = get_client().timereport

    read = tc.get_provider_report('test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == timereport_dict, read

    read = tc.get_provider_report('test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)),
                                                hours=True)
    assert read == timereport_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_timereport_content)
def test_get_company_timereport():
    tc = get_client().timereport

    read = tc.get_company_report('test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == timereport_dict, read

    read = tc.get_company_report('test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)),
                                  hours=True)
    assert read == timereport_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_timereport_content)
def test_get_agency_timereport():
    tc = get_client().timereport

    read = tc.get_agency_report('test', 'test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == timereport_dict, read

    read = tc.get_agency_report('test', 'test',\
        utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)),
                                  hours=True)
    assert read == timereport_dict, read

fin_report_dict = {'table':
     {'rows':
      [{'c':
        [{'v': '20100513'},
         {'v': 'odesk:odeskps'},
         {'v': '1'},
         {'v': '1'},
         {'v': '0'},
         {'v': '1'},
         {'v': 'Bug 1: Test'}]}],
         'cols':
         [{'type': 'date', 'label': 'worked_on'},
          {'type': 'string', 'label': 'assignment_team_id'},
          {'type': 'number', 'label': 'hours'},
          {'type': 'number', 'label': 'earnings'},
          {'type': 'number', 'label': 'earnings_offline'},
          {'type': 'string', 'label': 'task'},
          {'type': 'string', 'label': 'memo'}]}}


def patched_urlopen_fin_report_content(*args, **kwargs):
    return MicroMock(data=json.dumps(fin_report_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_billings():
    fr = get_client().finreport

    read = fr.get_provider_billings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_teams_billings():
    fr = get_client().finreport

    read = fr.get_provider_teams_billings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_companies_billings():
    fr = get_client().finreport

    read = fr.get_provider_companies_billings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_earnings():
    fr = get_client().finreport

    read = fr.get_provider_earnings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_teams_earnings():
    fr = get_client().finreport

    read = fr.get_provider_teams_earnings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_provider_companies_earnings():
    fr = get_client().finreport

    read = fr.get_provider_companies_earnings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_buyer_teams_billings():
    fr = get_client().finreport

    read = fr.get_buyer_teams_billings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_buyer_companies_billings():
    fr = get_client().finreport

    read = fr.get_buyer_companies_billings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_buyer_teams_earnings():
    fr = get_client().finreport

    read = fr.get_buyer_teams_earnings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_buyer_companies_earnings():
    fr = get_client().finreport

    read = fr.get_buyer_companies_earnings('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_financial_entities():
    fr = get_client().finreport

    read = fr.get_financial_entities('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


@patch('urllib3.PoolManager.urlopen', patched_urlopen_fin_report_content)
def test_get_financial_entities_provider():
    fr = get_client().finreport

    read = fr.get_financial_entities_provider('test', utils.Query(select=['1', '2', '3'], where=(utils.Q('2') > 1)))
    assert read == fin_report_dict, read


task_dict = {'tasks': 'task1'}


def patched_urlopen_task(*args, **kwargs):
    return MicroMock(data=json.dumps(task_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_get_team_tasks():
    task = get_client().task

    assert task.get_team_tasks(1, 1) == task_dict['tasks'], \
        task.get_team_tasks(1, 1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_get_company_tasks():
    task = get_client().task

    assert task.get_company_tasks(1) == task_dict['tasks'], \
        task.get_company_tasks(1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_get_team_specific_tasks():
    task = get_client().task

    assert task.get_team_specific_tasks(1, 1, [1, 1]) == task_dict['tasks'], \
        task.get_team_specific_tasks(1, 1, [1, 1])


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_get_company_specific_tasks():
    task = get_client().task

    assert task.get_company_specific_tasks(1, [1, 1]) == task_dict['tasks'], \
        task.get_company_specific_tasks(1, [1, 1])


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_post_team_task():
    task = get_client().task

    assert task.post_team_task(1, 1, 1, '1', 'ttt',
                               engagements=[1, 2],
                               all_in_company=True) == task_dict, \
        task.post_team_task(1, 1, 1, '1', 'ttt', engagements=[1, 2],
                            all_in_company=True)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_post_company_task():
    task = get_client().task

    assert task.post_company_task(1, 1, '1', 'ttt',
                                  engagements=[1, 2],
                                  all_in_company=True) == task_dict, \
        task.post_company_task(1, 1, '1', 'ttt')


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_put_team_task():
    task = get_client().task

    assert task.put_team_task(1, 1, 1, '1', 'ttt',
                              engagements=[1, 2],
                              all_in_company=True) == task_dict, \
        task.put_team_task(1, 1, 1, '1', 'ttt', engagements=[1, 2],
                           all_in_company=True)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_put_company_task():
    task = get_client().task

    assert task.put_company_task(1, 1, '1', 'ttt', engagements=[1, 2],
                                 all_in_company=True) == task_dict, \
        task.put_company_task(1, 1, '1', 'ttt', engagements=[1, 2],
                              all_in_company=True)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_archive_team_task():
    task = get_client().task

    assert task.archive_team_task(1, 1, 1) == task_dict, \
        task.archive_team_task(1, 1, 1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_archive_company_task():
    task = get_client().task

    assert task.archive_company_task(1, 1) == task_dict, \
        task.archive_company_task(1, 1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_unarchive_team_task():
    task = get_client().task

    assert task.unarchive_team_task(1, 1, 1) == task_dict, \
        task.unarchive_team_task(1, 1, 1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_unarchive_company_task():
    task = get_client().task

    assert task.unarchive_company_task(1, 1) == task_dict, \
        task.unarchive_company_task(1, 1)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_task)
def test_update_batch_tasks():
    task = get_client().task

    assert task.update_batch_tasks(1, "1;2;3") == task_dict, \
        task.update_batch_tasks(1, "1;2;3")


def test_gds_namespace():
    from odesk.namespaces import GdsNamespace
    gds = GdsNamespace(get_client())

    assert gds.post('test.url', {}) is None, \
        gds.post('test.url', {})
    assert gds.put('test.url', {}) is None, \
        gds.put('test.url', {})
    assert gds.delete('test.url', {}) is None, \
        gds.delete('test.url', {})


@patch('urllib3.PoolManager.urlopen', patched_urlopen)
def test_gds_namespace_get():
    from odesk.namespaces import GdsNamespace
    gds = GdsNamespace(get_client())
    result = gds.get('http://test.url')
    assert isinstance(result, dict), type(res)
    assert result == sample_json_dict, (result, sample_json_dict)


def setup_oauth():
    return OAuth(get_client())


def test_oauth_full_url():
    oa = setup_oauth()
    request_token_url = oa.full_url('oauth/token/request')
    access_token_url = oa.full_url('oauth/token/access')
    assert request_token_url == oa.request_token_url, request_token_url
    assert access_token_url == oa.access_token_url, access_token_url


def patched_httplib2_request(*args, **kwargs):
    return {'status': '200'},\
        'oauth_callback_confirmed=1&oauth_token=709d434e6b37a25c50e95b0e57d24c46&oauth_token_secret=193ef27f57ab4e37'

@patch('httplib2.Http.request', patched_httplib2_request)
def test_oauth_get_request_token():
    oa = setup_oauth()
    assert oa.get_request_token() == ('709d434e6b37a25c50e95b0e57d24c46',\
                                    '193ef27f57ab4e37')


@patch('httplib2.Http.request', patched_httplib2_request)
def test_oauth_get_authorize_url():
    oa = setup_oauth()
    assert oa.get_authorize_url() ==\
        'https://www.odesk.com/services/api/auth?oauth_token=709d434e6b37a25c50e95b0e57d24c46',\
        oa.get_authorize_url()
    assert oa.get_authorize_url('http://example.com/oauth/complete') ==\
        'https://www.odesk.com/services/api/auth?oauth_token=709d434e6b37a25c50e95b0e57d24c46&oauth_callback=http%3A%2F%2Fexample.com%2Foauth%2Fcomplete',\
        oa.get_authorize_url('http://example.com/oauth/complete')

def patched_httplib2_access(*args, **kwargs):
    return {'status': '200'},\
        'oauth_token=aedec833d41732a584d1a5b4959f9cd6&oauth_token_secret=9d9cccb363d2b13e'


@patch('httplib2.Http.request', patched_httplib2_access)
def test_oauth_get_access_token():
    oa = setup_oauth()
    oa.request_token = '709d434e6b37a25c50e95b0e57d24c46'
    oa.request_token_secret = '193ef27f57ab4e37'
    assert oa.get_access_token('9cbcbc19f8acc2d85a013e377ddd4118') ==\
     ('aedec833d41732a584d1a5b4959f9cd6', '9d9cccb363d2b13e')


job_profiles_dict = {'profiles': {'profile': [
    {
        'amount': '',
        'as_hrs_per_week': '0',
        'as_job_type': 'Hourly',
        'as_opening_access': 'private',
        'as_opening_recno': '111',
        'as_opening_title': 'Review website and improve copy writing',
        'as_provider': '111',
        'as_rate': '$10.00',
        'as_reason': 'Job was cancelled or postponed',
        'as_reason_api_ref': '',
        'as_reason_recno': '72',
        'as_recno': '1',
        'as_status': 'Closed',
        'as_to': '11/2011',
        'as_total_charge': '84',
        'as_total_hours': '3.00',
        'op_desc_digest': 'Test job 1.',
        'op_description': 'Test job 1.',
        'ciphertext': '~~111111111',
        'ui_job_profile_access': 'odesk',
        'ui_opening_status': 'Active',
        'version': '1'
    },
    {
        'amount': '',
        'as_hrs_per_week': '0',
        'as_job_type': 'Hourly',
        'as_opening_access': 'private',
        'as_opening_recno': '222',
        'as_opening_title': 'Review website and improve copy writing',
        'as_provider': '222',
        'as_rate': '$10.00',
        'as_reason': 'Job was cancelled or postponed',
        'as_reason_api_ref': '',
        'as_reason_recno': '72',
        'as_recno': '2',
        'as_status': 'Closed',
        'as_to': '11/2011',
        'as_total_charge': '84',
        'as_total_hours': '3.00',
        'ciphertext': '~~222222222',
        'op_desc_digest': 'Test job 2.',
        'op_description': 'Test job 2.',
        'ui_job_profile_access': 'odesk',
        'ui_opening_status': 'Active',
        'version': '1'
    },
]}}

job_profile_dict = {'profile':
    {
        'amount': '',
        'as_hrs_per_week': '0',
        'as_job_type': 'Hourly',
        'as_opening_access': 'private',
        'as_opening_recno': '111',
        'as_opening_title': 'Review website and improve copy writing',
        'as_provider': '111',
        'as_rate': '$10.00',
        'as_reason': 'Job was cancelled or postponed',
        'as_reason_api_ref': '',
        'as_reason_recno': '72',
        'as_recno': '1',
        'as_status': 'Closed',
        'as_to': '11/2011',
        'as_total_charge': '84',
        'as_total_hours': '3.00',
        'op_desc_digest': 'Test job 1.',
        'op_description': 'Test job 1.',
        'ciphertext': '~~111111111',
        'ui_job_profile_access': 'odesk',
        'ui_opening_status': 'Active',
        'version': '1'
    }
}


def patched_urlopen_single_job(*args, **kwargs):
    return MicroMock(data=json.dumps(job_profile_dict), status=200)


def patched_urlopen_multiple_jobs(*args, **kwargs):
    return MicroMock(data=json.dumps(job_profiles_dict), status=200)


@patch('urllib3.PoolManager.urlopen', patched_urlopen_single_job)
def test_single_job_profile():
    job = get_client().job

    # Test full_url
    full_url = job.full_url('jobs/111')
    assert full_url == 'https://www.odesk.com/api/profiles/v1/jobs/111', \
        full_url

    # Test input parameters
    try:
        job.get_job_profile({})
        raise Exception('Request should raise ValueError exception.')
    except ValueError as e:
        assert 'Invalid job key' in str(e)
    try:
        job.get_job_profile(['~~{0}'.format(x) for x in range(21)])
        raise Exception('Request should raise ValueError exception.')
    except ValueError as e:
        assert 'Number of keys per request is limited' in str(e)
    try:
        job.get_job_profile(['~~111111', 123456])
        raise Exception('Request should raise ValueError exception.')
    except ValueError as e:
        assert 'List should contain only job keys not recno' in str(e)

    # Get single job profile test
    assert job.get_job_profile('~~111111111') == job_profile_dict['profile'], \
        job.get_job_profile('~~111111111')


@patch('urllib3.PoolManager.urlopen', patched_urlopen_multiple_jobs)
def test_multiple_job_profiles():
    job = get_client().job

    # Test full_url
    full_url = job.full_url('jobs/~~111;~~222')
    assert full_url == \
        'https://www.odesk.com/api/profiles/v1/jobs/~~111;~~222', full_url

    # Get multiple job profiles test
    assert job.get_job_profile(['~~111111111', '~~222222222']) == \
        job_profiles_dict['profiles']['profile'], \
        job.get_job_profile(['~~111111111', '~~222222222'])


#======================
# UTILS TESTS
#======================
def test_decimal_default():
    from odesk.utils import decimal_default

    value = '0.132'

    eq_('{"value": "0.132"}', json.dumps({'value': Decimal(value)},
                                         default=decimal_default))

    value = '0'

    eq_('{"value": "0"}', json.dumps({'value': Decimal(value)},
                                     default=decimal_default))

    value = '10'

    eq_('{"value": "10"}', json.dumps({'value': Decimal(value)},
                                      default=decimal_default))
