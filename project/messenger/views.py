from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from .twitter_utils import create_or_update_twitter, handle_verify_challenge, handle_inbound_event, get_twitter
from .models import Event


def index(request):
    account_id = request.GET.get('account_id')
    client = get_twitter(account_id)
    result = client.get_home_timeline()
    return HttpResponse(result)


def message(request):
    account_id = request.GET.get('account_id')
    text = request.GET.get('text')
    user_id = request.GET.get('user_id')
    client = get_twitter(account_id)
    result = client.send_direct_message(user_id, text)
    return HttpResponse(result)


def status(request):
    account_id = request.GET.get('account_id')
    text = request.GET.get('text')
    in_reply_to_status_id = request.GET.get('in_reply_to_status_id')
    client = get_twitter(account_id)
    result = client.update_status(text, in_reply_to_status_id)
    return HttpResponse(result)


def events(request):
    account_id = request.GET.get('account_id', None)
    msg_list = Event.objects.filter(account__id=account_id)
    return HttpResponse(msg_list)


def create_twitter(request):
    account = create_or_update_twitter(
        name=request.GET.get('name'),
        company_property=request.GET.get('company_property'),
        account_id=request.GET.get('account_id', None),
        twitter_consumer_key=request.GET.get('twitter_consumer_key'),
        twitter_consumer_secret=request.GET.get('twitter_consumer_secret'),
        twitter_access_token=request.GET.get('twitter_access_token'),
        twitter_access_token_secret=request.GET.get('twitter_access_token_secret'),
        twitter_environment=request.GET.get('twitter_environment'))

    return HttpResponse(f'Account id: {account.id}')


@csrf_exempt
def twitter_webhook_url(request, account_id):
    if request.method == 'GET':
        crc_token = request.GET['crc_token']
        response_data = handle_verify_challenge(crc_token, account_id)
        return HttpResponse(response_data, content_type='application/json')
    elif request.method == 'POST':
        signature = request.META.get('HTTP_X_TWITTER_WEBHOOKS_SIGNATURE')
        return handle_inbound_event(signature, request.body, account_id)
