#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import datetime
from django.db import models
from juser.models import User, UserGroup
# Create your models here.


ASSET_ENV = (
	(1, '生产环境'),
	(2, '测试环境'),
)

ASSET_STATUS = (
	(1, '已上线'),
	(2, '未上线'),
	(3, '已下架'),
)

ASSET_TYPE = (
	(1, '物理机'),
	(2, '虚拟机'),
	(3, '交换机'),
	(4, '路由器'),
	(5, '防火墙'),
	(6, 'Docker'),
	(7, '其他'),
)


class AssetGroup(models.Model):
	'''
	资产组表(主机组)
	'''
	GROUP_TYPE = (
		('P', 'PRIVATE'),
		('A', 'ASSET'),
	)
	name = models.CharField(max_length=80, unique=True)
	comment = models.CharField(max_length=160, blank=True, null=True)

	def __unicode__(self):
		return self.name


class IDC(models.Model):
	name = models.CharField(max_length=32, verbose_name='机房名称')
	bandwidth = models.CharField(max_length=32, blank=True, null=True, default='', verbose_name='上联带宽')
	available_bandwidth = models.CharField(max_length=32, blank=True, null=True, default='', verbose_name='CDN可用上联带宽')
	linkman = models.CharField(max_length=16, blank=True, null=True, default='', verbose_name='联系人')
	phone = models.CharField(max_length=32, blank=True, null=True, default='', verbose_name='联系电话')
	address = models.CharField(max_length=128, blank=True, null=True, default='', verbose_name='机房地址')
	network = models.TextField(blank=True, null=True, default='', verbose_name='IP地址段')
	date_added = models.DateField(auto_now=True, null=True)
	operator = models.CharField(max_length=32, blank=True, null=True, default='', verbose_name='运营商')
	comment = models.CharField(max_length=128, blank=True, null=True, default='', verbose_name='备注')

	def __unicode__(self):
		return self.name

	class Meta:
		verbose_name = 'IDC机房'
		verbose_name_plural = verbose_name


class Asset(models.Model):
	'''
	资产表
	'''
	ip = models.CharField(max_length=32, blank=True, null=True, verbose_name='主机IP')
	other_ip = models.CharField(max_length=255, blank=True, null=True, verbose_name='其他IP')
	hostname = models.CharField(max_length=128, unique=True, verbose_name='主机名')		# 主机名不能出现相同的
	port = models.IntegerField(blank=True, null=True, verbose_name='端口号')
	group = models.ManyToManyField(AssetGroup, blank=True, verbose_name='所属主机组')		# 多对对关联到主机组表(AssetGroup)
	username = models.CharField(max_length=16, blank=True, null=True, verbose_name='管理用户名')
	password = models.CharField(max_length=256, blank=True, null=True, verbose_name='密码')
	use_default_auth = models.BooleanField(default=True, verbose_name='使用默认管理账号')
	idc = models.ForeignKey(IDC, blank=True, null=True, on_delete=models.SET_NULL, verbose_name='机房')		# models.SET_NULL, 表示当外键IDC被删除时, 该IDC字段设置为NULL
	mac = models.CharField(max_length=20, blank=True, null=True, verbose_name='MAC地址')
	remote_ip = models.CharField(max_length=16, blank=True, null=True, verbose_name='远程管理卡IP')
	brand = models.CharField(max_length=64, blank=True, null=True, verbose_name='硬件厂商型号')
	cpu = models.CharField(max_length=64, blank=True, null=True, verbose_name='CPU')
	memory = models.CharField(max_length=128, blank=True, null=True, verbose_name='内存')
	disk = models.CharField(max_length=1024, blank=True, null=True, verbose_name='硬盘')
	system_type = models.CharField(max_length=32, blank=True, null=True, verbose_name='系统类型')
	system_version = models.CharField(max_length=8, blank=True, null=True, verbose_name='系统版本号')
	system_arch = models.CharField(max_length=16, blank=True, null=True, verbose_name='系统平台')
	cabinet = models.CharField(max_length=32, blank=True, null=True, verbose_name='机柜号')
	position = models.IntegerField(blank=True, null=True, verbose_name='机器位置')
	number = models.CharField(max_length=32, blank=True, null=True, verbose_name='资产编号')
	status = models.IntegerField(choices=ASSET_STATUS, blank=True, null=True, default=1, verbose_name='机器状态')
	asset_type = models.IntegerField(choices=ASSET_TYPE, blank=True, null=True, verbose_name='主机类型')
	env = models.IntegerField(choices=ASSET_ENV, blank=True, null=True, verbose_name='运行环境')
	sn = models.CharField(max_length=128, blank=True, null=True, verbose_name='SN编号')
	date_added = models.DateTimeField(auto_now=True, null=True)
	is_active = models.BooleanField(default=True, verbose_name='是否激活')
	comment = models.CharField(max_length=128, blank=True, null=True, verbose_name='备注')

	def __unicode__(self):
		return self.ip


class AssetRecord(models.Model):
	'''
	资产信息变更记录表, 谁更改了资产信息, 并且记录变更信息的前后对比
	'''
	asset = models.ForeignKey(Asset)		# 外键关联到Asset表
	username = models.CharField(max_length=30, null=True)
	alert_time = models.DateTimeField(auto_now_add=True)		# auto_now_add时间创建后不能修改
	content = models.TextField(blank=True, null=True)
	comment = models.TextField(blank=True, null=True)


class AssetAlias(models.Model):
	user = models.ForeignKey(User)
	asset = models.ForeignKey(Asset)
	alias = models.CharField(max_length=100, blank=True, null=True)

	def __unicode__(self):
		return self.alias
