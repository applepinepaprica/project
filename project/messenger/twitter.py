import base64
import json
import oauth2
import urllib.parse
import requests


# twitter utils. This class create webhooks, sibscribe, send messages
# this part of code can be in helper document like utils.py
class Twitter(object):
    def __init__(self, **kwargs):
        self.data = kwargs
        self.base_url = 'https://api.twitter.com/'

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
