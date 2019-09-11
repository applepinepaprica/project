import base64
import hashlib
import hmac
import json
import oauth2
import urllib.parse
import requests
import twitter
from django.http import HttpResponse

from project import settings
from .models import Account, AccountType, AccountSetting


# twitter utils. This class create webhooks, sibscribe, send messages
# this part of code can be in helper document like utils.py
class Twitter(object):
    def __init__(self, **kwargs):
        self.data = kwargs
        self.base_url = 'https://api.twitter.com/'

    @staticmethod
    def get_twitter(account_id):
        return Twitter(twitter_consumer_key=AccountSetting.objects.get(key='twitter_consumer_key',
                                                                       account__id=account_id).value,
                       twitter_consumer_secret=AccountSetting.objects.get(key='twitter_consumer_secret',
                                                                          account__id=account_id).value,
                       twitter_access_token=AccountSetting.objects.get(key='twitter_access_token',
                                                                       account__id=account_id).value,
                       twitter_access_token_secret=AccountSetting.objects.get(key='twitter_access_token_secret',
                                                                              account__id=account_id).value,
                       twitter_environment=AccountSetting.objects.get(key='twitter_environment',
                                                                      account__id=account_id).value)

    def get_application(self):
        consumer_key = self.data['twitter_consumer_key']
        consumer_secret = self.data['twitter_consumer_secret']
        access_token = self.data['twitter_access_token']
        access_token_secret = self.data['twitter_access_token_secret']
        consumer = oauth2.Consumer(key=consumer_key, secret=consumer_secret)
        token = oauth2.Token(key=access_token, secret=access_token_secret)
        client = oauth2.Client(consumer, token)
        return client

    def create_webhook(self):
        webhook_id, _ = self.get_webhook_id()
        # Check if webhook exists, if YES delete old and create new one
        if webhook_id:
            self.delete_exists_webhook()

        app = self.get_application()
        webhook_endpoint = urllib.parse.quote_plus(self.data['webhook_url'])
        url = '{}1.1/account_activity/all/{}/webhooks.json?url={}'.format(
            self.base_url,
            self.data['twitter_environment'],
            webhook_endpoint
        )
        response, content = app.request(url, method='POST')
        if response['status'] == 200:
            data = json.loads(content.decode('utf-8'))
            webhook_id = data['id']
        return webhook_id is not None

    def get_webhook_id(self):
        webhook_id = None
        env_name = None
        headers = {
            'Authorization': 'Bearer {}'.format(self.get_access_token())
        }
        response = requests.get(
            '{}1.1/account_activity/all/webhooks.json'.format(self.base_url),
            headers=headers
        )

        if response.status_code == 200:
            data = response.json()
            if data['environments'][0].get('webhooks'):
                webhook_id = int(response.json()['environments'][0].get('webhooks')[0]['id'])
            env_name = response.json()['environments'][0]['environment_name']
        return webhook_id, env_name

    def subscribe(self):
        app = self.get_application()
        url = '{}1.1/account_activity/all/{}/subscriptions.json'.format(
            self.base_url,
            self.data['twitter_environment']
        )
        response, _ = app.request(url, method='POST')
        return response['status'] == 204

    def delete_exists_webhook(self):
        app = self.get_application()
        webhook_id, env_name = self.get_webhook_id()
        if webhook_id and env_name:
            app.request('{}1.1/account_activity/all/{}/webhooks/{}.json'.format(
                self.base_url,
                env_name,
                webhook_id
            ), method='DELETE')
        else:
            raise Exception('Not enough information')

    def get_access_token(self):
        key_secret = '{}:{}'.format(
            self.data['twitter_consumer_key'],
            self.data['twitter_consumer_secret']
        ).encode('ascii')
        b64_encoded_key = base64.b64encode(key_secret)
        b64_encoded_key = b64_encoded_key.decode('ascii')
        auth_url = '{}oauth2/token'.format(self.base_url)
        auth_headers = {
            'Authorization': 'Basic {}'.format(b64_encoded_key),
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }
        auth_data = {
            'grant_type': 'client_credentials'
        }

        auth_resp = requests.post(auth_url, headers=auth_headers, data=auth_data)
        if auth_resp.status_code == 200:
            return auth_resp.json()['access_token']
        raise Exception(auth_resp.json()['errors'][0]['message'])

    def send_direct_message(self, user_id, text):
        app = self.get_application()
        url = '{}1.1/direct_messages/events/new.json'.format(self.base_url)
        data = {
            'event': {
            'message_create': {
                'message_data': {'text': text},
                'target': {'recipient_id': user_id}},
                'type': 'message_create'}
            }
        response, content = app.request(url, body=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')
        return response['status']

    def get_home_timeline(self):
        app = self.get_application()
        url = '{}1.1/statuses/home_timeline.json'.format(self.base_url)
        response, content = app.request(url, headers={'Content-Type': 'application/json'}, method='GET')
        data = json.loads(content.decode('utf-8'))
        return data

    def update_status(self, text, in_reply_to_status_id=None):
        app = self.get_application()
        url = '{}1.1/statuses/update.json?status={}&in_reply_to_status_id={}'.format(self.base_url, text, in_reply_to_status_id)
        response, content = app.request(url, headers={'Content-Type': 'application/json'}, method='POST')
        return response['status']

    def create_webhook_and_subscribe(self):
        if self.create_webhook():
            self.subscribe()
        else:
            raise Exception('Could not create webhook and subscribe user')

    # create Twitter account
    def create_or_update_twitter(name, company_property, account_id=None, **account_settings):

        # check account settings are provided
        if account_id is None:
            try:
                twitter_consumer_key = account_settings['twitter_consumer_key']
                twitter_consumer_secret = account_settings['twitter_consumer_secret']
                twitter_access_token = account_settings['twitter_access_token']
                twitter_access_token_secret = account_settings['twitter_access_token_secret']
                twitter_environment = account_settings['twitter_environment']
            except KeyError:
                raise Exception('Missing settings')
        else:
            twitter_consumer_key = AccountSetting.objects.get(account__id=account_id, key='twitter_consumer_key').value
            twitter_consumer_secret = AccountSetting.objects.get(account__id=account_id,
                                                                 key='twitter_consumer_secret').value
            twitter_access_token = AccountSetting.objects.get(account__id=account_id, key='twitter_access_token').value
            twitter_access_token_secret = AccountSetting.objects.get(account__id=account_id,
                                                                     key='twitter_access_token_secret').value
            twitter_environment = AccountSetting.objects.get(account__id=account_id, key='twitter_environment').value

        # validate account settings
        try:
            # OAuth process, using the keys and tokens
            api = twitter.Api(
                consumer_key=twitter_consumer_key,
                consumer_secret=twitter_consumer_secret,
                access_token_key=twitter_access_token,
                access_token_secret=twitter_access_token_secret
            )
            app = api.VerifyCredentials()
            twitter_id = app.id
        except Exception:
            raise Exception('Twitter authentication error, please check your settings')

        # create account
        if account_id is None:
            # save new account
            account = Account.objects.create(name=name, application=AccountType.TWITTER,
                                             company_property=company_property)

        # update account
        else:
            try:
                # update account
                account = Account.objects.get(id=account_id, company_property=company_property)
                account.name = name
                account.save()
            except Account.DoesNotExist:
                raise Exception('Account not found')

        # update account settings
        AccountSetting.objects.update_or_create(key='twitter_consumer_key', account=account,
                                                value=twitter_consumer_key)
        AccountSetting.objects.update_or_create(key='twitter_consumer_secret', account=account,
                                                value=twitter_consumer_secret)
        AccountSetting.objects.update_or_create(key='twitter_access_token', account=account,
                                                value=twitter_access_token)
        AccountSetting.objects.update_or_create(key='twitter_access_token_secret', account=account,
                                                value=twitter_access_token_secret)
        AccountSetting.objects.update_or_create(key='twitter_environment', account=account,
                                                value=twitter_environment)

        # generate webhook url
        webhook_url = '{}webhooks/twitter/{id}/'.format(settings.APP_URL, id=account.id)
        data = {
            'webhook_url': webhook_url,
            'twitter_consumer_key': twitter_consumer_key,
            'twitter_consumer_secret': twitter_consumer_secret,
            'twitter_access_token': twitter_access_token,
            'twitter_access_token_secret': twitter_access_token_secret,
            'twitter_environment': twitter_environment
        }

        # Create webhook
        application = Twitter(**data)
        application.create_webhook_and_subscribe()

        twitter_contact_url = 'https://twitter.com/messages/compose?recipient_id={twitter_id}'.format(twitter_id=twitter_id)
        AccountSetting.objects.update_or_create(key='twitter_user_id', account=account,
                                                value=twitter_id)
        AccountSetting.objects.update_or_create(key='twitter_contact_url', account=account,
                                                value=twitter_contact_url)
        # widget = WidgetSettings.objects.get(company_property=company_property)
        # if account_id is None:
        #     widget.twitter_display = True
        # widget.twitter_contact_url = twitter_contact_url
        # widget.save()

        return account


# Twitter webhook. This part of code should be in views.py where requests are handled
def twitter_webhook(request, account_id):

    if request.method == 'GET':
        # handle verify challenge
        secret = AccountSetting.objects.get(key='twitter_consumer_secret', account__id=account_id).value
        crc_token = request.GET['crc_token']
        sha256_hash_digest = hmac.new(key=bytes(secret, 'utf-8'), msg=bytes(crc_token, 'utf-8'),
                                      digestmod=hashlib.sha256).digest()
        response_data = {'response_token': 'sha256=' + str(base64.b64encode(sha256_hash_digest), 'utf-8')}
        return HttpResponse(json.dumps(response_data), content_type='application/json')

    elif request.method == 'POST':
        # authenticate request
        signature = request.META.get('HTTP_X_TWITTER_WEBHOOKS_SIGNATURE')
        consumer_secret = AccountSetting.objects.get(key='twitter_consumer_secret', account__id=account_id).value
        sha256_hash_digest = hmac.new(consumer_secret.encode(), request.body, hashlib.sha256).digest()
        base64_hash = base64.b64encode(sha256_hash_digest)

        if hmac.compare_digest(signature, 'sha256={hash}'.format(hash=base64_hash.decode())):
            # authenticated, check if message event
            event = json.loads(request.body.decode('utf-8'))
            msg_list = event.get('direct_message_events')

            if msg_list:
                print(msg_list)
            #     # ignore if outbound message
            #     sender_id = msg_list[0]['message_create']['sender_id']
            #     user_id = AccountSetting.objects.get(key='twitter_user_id', account_id=account_id).value
            #     if sender_id == user_id:
            #         return HttpResponse(status=200)
            #     # save if inbound message
            #     event['account_id'] = account_id
            #     messenger = MessageFactory.factory()
            #     messenger.receive(AccountType.TWITTER, event)
            #     return HttpResponse(status=201)

            return HttpResponse(status=200)

    return HttpResponse(status=403)
