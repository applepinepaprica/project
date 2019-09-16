import base64
import twitter
import hashlib
import hmac
import json
from django.http import HttpResponse

from project import settings
from .models import Account, AccountType, AccountSetting, Event, EventType
from .twitter import Twitter


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


def handle_verify_challenge(crc_token, account_id):
    secret = AccountSetting.objects.get(key='twitter_consumer_secret', account__id=account_id).value
    sha256_hash_digest = hmac.new(key=bytes(secret, 'utf-8'), msg=bytes(crc_token, 'utf-8'),
                                  digestmod=hashlib.sha256).digest()
    response_data = {'response_token': 'sha256=' + str(base64.b64encode(sha256_hash_digest), 'utf-8')}
    return json.dumps(response_data)


def handle_inbound_event(signature, body, account_id):
    # authenticate request
    consumer_secret = AccountSetting.objects.get(key='twitter_consumer_secret', account__id=account_id).value
    sha256_hash_digest = hmac.new(consumer_secret.encode(), body, hashlib.sha256).digest()
    base64_hash = base64.b64encode(sha256_hash_digest)

    if hmac.compare_digest(signature, 'sha256={hash}'.format(hash=base64_hash.decode())):
        # authenticated, check if message event
        event = json.loads(body.decode('utf-8'))
        msg_list = event.get('direct_message_events')

        if msg_list:
            # ignore if outbound message
            sender_id = msg_list[0]['message_create']['sender_id']
            user_id = AccountSetting.objects.get(key='twitter_user_id', account__id=account_id).value
            if sender_id == user_id:
                return HttpResponse(status=200)
            # save if inbound message
            account = Account.objects.get(id=account_id)
            text = msg_list[0]['message_create']['message_data']['text']
            Event.objects.create(account=account, event=msg_list, type=EventType.MESSAGE,
                                 author=sender_id, text=text)
            # event['account_id'] = account_id
            # messenger = MessageFactory.factory()
            # messenger.receive(AccountType.TWITTER, event)
            return HttpResponse(status=201)

        msg_list = event.get('tweet_create_events')
        if msg_list:
            sender_id = msg_list[0]['user']['id_str']
            user_id = AccountSetting.objects.get(key='twitter_user_id', account__id=account_id).value
            if sender_id == user_id:
                return HttpResponse(status=200)
            account = Account.objects.get(id=account_id)
            text = msg_list[0]['text']
            Event.objects.create(account=account, event=msg_list, type=EventType.TWEET,
                                 author=sender_id, text=text)
            return HttpResponse(status=201)

        return HttpResponse(status=200)

    return HttpResponse(status=403)
