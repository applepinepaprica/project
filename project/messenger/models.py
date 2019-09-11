from django.db import models
from enum import Enum


class AccountType(Enum):
    TWITTER = "Twitter"
    TELEGRAM = "Telegram"


class Account(models.Model):
    name = models.CharField(max_length=20)
    application = models.CharField(max_length=20, choices=[(tag, tag.value) for tag in AccountType])
    company_property = models.CharField(max_length=20)


class AccountSetting(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    key = models.CharField(max_length=40)
    value = models.CharField(max_length=40)
