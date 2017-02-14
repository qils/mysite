#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import time
from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.


class UserGroup(models.Model):
	'''
	用户组表
	'''

	name = models.CharField(max_length=80, unique=True)
	comment = models.CharField(max_length=160, blank=True, null=True)

	def __unicode__(self):
		return self.name		# 显示组名称


class User(AbstractUser):
	'''
	用户表
	'''
	user_role_choices = (
		('SU', 'SuperUser'),
		('GA', 'GroupAdmin'),
		('CU', 'CommonUser'),
	)
	name = models.CharField(max_length=80)
	uuid = models.CharField(max_length=100)
	role = models.CharField(max_length=2, choices=user_role_choices, default='CU')
	group = models.ManyToManyField(UserGroup)		# 多对多关联到UserGroup表
	ssh_key_pwd = models.CharField(max_length=200)

	def __unicode__(self):
		return self.username		# 显示用户名称


class AdminGroup(models.Model):
	'''
	用户可以管理的用户组表, 或者某个用户组的管理员是该用户
	'''
	user = models.ForeignKey(User)		# 外键关联到User表
	group = models.ForeignKey(UserGroup)		# 外键关联到UserGroup表

	def __unicode__(self):
		return '%s: %s' % (self.user.username, self.group.name)


class Document(models.Model):
	'''
	文档表
	'''
	def upload_to(self, filename):
		return 'upload/' + str(self.user.id) + time.strftime('/%Y/%m/%d', time.localtime()) + filename

	docfile = models.FileField(upload_to=upload_to)		# 文件上传字段
	user = models.ForeignKey(User)		# 外键关联到User表