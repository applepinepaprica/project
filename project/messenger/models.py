from django.db import models
from enum import Enum


class AccountType(Enum):
    TWITTER = "Twitter"


class Account(models.Model):
    name = models.CharField(max_length=20)
    application = models.CharField(max_length=20, choices=[(tag, tag.value) for tag in AccountType])
    company_property = models.CharField(max_length=20)

    def __str__(self):
        return f'Name:{self.name}, application: {self.application}, company_property: {self.company_property}'


class AccountSetting(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    key = models.CharField(max_length=40)
    value = models.CharField(max_length=40)

    def __str__(self):
        return f'Account:{self.account_id}, key: {self.key}, value: {self.value}'
