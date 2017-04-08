#!/usr/bin/env python
# --*-- coding: utf-8

from django.db import models
from jasset.models import Asset, AssetGroup
from juser.models import User, UserGroup

# Create your models here.


class PermLog(models.Model):
	datetime = models.DateTimeField(auto_now_add=True)
	action = models.CharField(max_length=100, null=True, blank=True, default='')
	results = models.CharField(max_length=1000, null=True, blank=True, default='')
	is_success = models.BooleanField(default=False)
	is_finish = models.BooleanField(default=False)


class PermSudo(models.Model):
	name = models.CharField(max_length=100, unique=True)
	date_added = models.DateTimeField(auto_now=True)
	commands = models.TextField()
	comment = models.CharField(max_length=100, null=True, blank=True, default='')

	def __unicode__(self):
		return self.name


class PermRole(models.Model):
	name = models.CharField(max_length=100, unique=True)
	comment = models.CharField(max_length=100, null=True, blank=True, default='')
	password = models.CharField(max_length=512)
	key_path = models.CharField(max_length=100)
	date_added = models.DateTimeField(auto_now=True)
	sudo = models.ManyToManyField(PermSudo, related_name='perm_role')

	def __unicode__(self):
		return self.name


class PermRule(models.Model):
	date_added = models.DateTimeField(auto_now=True)
	name = models.CharField(max_length=100, unique=True)
	comment = models.CharField(max_length=100)
	asset = models.ManyToManyField(Asset, related_name='perm_rule')		# 多对多关联到资产表
	asset_group = models.ManyToManyField(AssetGroup, related_name='perm_rule')		# 多对对关联到资产组表
	user = models.ManyToManyField(User, related_name='perm_rule')			# 多对多关联到用户表
	user_group = models.ManyToManyField(UserGroup, related_name='perm_rule')		# 多对多关联到用户组表
	role = models.ManyToManyField(PermSudo, related_name='perm_rule')		# 多对多关联到PermRole表

	def __unicode__(self):
		return self.name


class PermPush(models.Model):
	asset = models.ForeignKey(Asset, related_name='perm_push')
	role = models.ForeignKey(PermRole, related_name='perm_push')
	is_public_key = models.BooleanField(default=False)
	is_password = models.BooleanField(default=False)
	success = models.BooleanField(default=False)
	result = models.TextField(default='')
	date_added = models.DateTimeField(auto_now=True)
