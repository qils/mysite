#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import time
from django.db import models
from juser.models import User
# Create your models here.


class Log(models.Model):
	'''
	主机登录日志
	'''
	user = models.CharField(max_length=20, null=True)		# 登录用户
	host = models.CharField(max_length=200, null=True)		# 登录主机名
	remote_ip = models.CharField(max_length=100)		# 客户端IP
	login_type = models.CharField(max_length=100)		# 登录类型, Websocket, 或者ssh登录
	log_path = models.CharField(max_length=100)		# 日志路径
	start_time = models.DateTimeField(null=True)		# 登录设备时间
	pid = models.IntegerField()
	is_finished = models.BooleanField(default=False)		# 是否退出设备
	end_time = models.DateTimeField(null=True)		# 登出设备时间
	filename = models.CharField(max_length=40)

	def __unicode__(self):
		return self.log_path


class Alert(models.Model):
	msg = models.CharField(max_length=20)
	time = models.DateTimeField(null=True)
	is_finished = models.BigIntegerField(default=False)


class TtyLog(models.Model):
	log = models.ForeignKey(Log)
	datetime = models.DateTimeField(auto_now=True)
	cmd = models.CharField(max_length=200)


class ExecLog(models.Model):
	user = models.CharField(max_length=100)
	host = models.TextField()
	cmd = models.TextField()
	remote_ip = models.CharField(max_length=100)
	result = models.TextField(default='')
	datetime = models.DateTimeField(auto_now=True)


class FileLog(models.Model):
	user = models.CharField(max_length=100)
	host = models.TextField()
	filename = models.TextField()
	type = models.CharField(max_length=20)
	remote_ip = models.CharField(max_length=100)
	result = models.TextField(default='')
	datetime = models.DateTimeField(auto_now=True)


class TermLog(models.Model):
	user = models.ManyToManyField(User)
	logPath = models.TextField()
	filename = models.CharField(max_length=40)
	logPWD = models.TextField()
	nick = models.TextField(null=True)
	log = models.TextField(null=True)
	history = models.TextField(null=True)
	timestamp = models.IntegerField(default=int(time.time()))
	datetimestamp = models.DateTimeField(auto_now_add=True)
