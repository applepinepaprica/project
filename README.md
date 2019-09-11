## App for sending and receiving direct messages and tweets

### How to run project:
* Run ngrok
* Write url from ngrok to ALLOWED_HOSTS and APP_URL in project/setting.py 
* Run commands:
```
python3.6 -m venv venv
source venv/bin/activate
pip install requirements.txt
cd project
python manage.py migrate
python manage.py runserver
```
The project will be available here: http://localhost:8000/

### Available endpoints:

* Create account, register webhook and subscribe:
```
http://localhost:8000/create_twitter?name=name&company_property=company&twitter_consumer_key=&twitter_consumer_secret=&twitter_access_token=&twitter_access_token_secret=&twitter_environment=
```
All values must be without quotes
This endpoint returns account id for other requests

* Register webhook and subscribe if account exists:
```
http://localhost:8000/create_twitter/?name=name&company_property=company&account_id=1
```

* Send message:
```
http://localhost:8000/message?account_id=&user_id=&text=
```

* Update status
```
localhost:8000/status?account_id=&text=&in_reply_to_status_id=None
```

* Get timeline
```
http://localhost:8000/?account_id=
```

* Get inbound messages and tweets received by webhook
```
http://localhost:8000/events/?account_id=
```
