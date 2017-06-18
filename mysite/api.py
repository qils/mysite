#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import uuid
import pwd
import logging
import hashlib
import random
import datetime
import subprocess
from mysite import settings
from Crypto.Cipher import AES		# 调用AES加密字符
from binascii import b2a_hex, a2b_hex
from django.core.paginator import Paginator, EmptyPage, InvalidPage
from django.http import HttpResponse, HttpResponseRedirect, Http404
from mysite.models import Setting
from juser.models import User, UserGroup
from jasset.models import Asset, AssetGroup, AssetRecord, IDC
from jlog.models import Log
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.shortcuts import render_to_response
from django.template import RequestContext


def get_asset_info(asset):
	'''
	获取资产相关的管理账号, 端口, ip, 主机名等信息
	'''
	default = Setting.objects.get(name='default')
	info = {'hostname': asset.hostname, 'ip': asset.ip}		# 添加主机名称, 主机IP信息
	if asset.use_default_auth:
		if default:
			info['username'] = default.field1		# 添加主机账号
			try:
				info['password'] = CRYPTOR.decrypt(default.field3)		# 添加主机密码
			except ServerError, e:
				pass
			if os.path.isfile(default.field4):
				info['ssh_key'] = default.field4		# 添加秘钥目录
	else:
		info['username'] = asset.username
		info['password'] = CRYPTOR.decrypt(asset.password)

	try:
		info['port'] = int(asset.port)
	except ValueError:
		info['port'] = int(default.field2)		# 添加主机端口


def list_drop_str(a_list, a_str):
	'''
	从alist中删除满足a_str的成员
	'''
	for i in a_list:
		if i == a_str:
			a_list.remove(a_str)
	return a_list


class ServerError(Exception):
	'''
	自定义异常
	'''
	pass


def page_list_return(total, current):
	'''
	分页, 返回本次分页最小页到最大页数列表
	'''
	min_page = current - 2 if current - 4 > 0 else 1
	max_page = min_page + 4 if min_page + 4 < total else total

	return range(min_page, max_page+1)


def pages(post_objects, request):
	'''
	分页通用函数, 返回分页对象元组
	'''
	paginator = Paginator(post_objects, 20)		# 创建每页显示20条数据的分页对象
	try:
		current_page = int(request.GET.get('page', 1))		# 获取当前页码, 默认当前页码为1
	except ValueError:
		current_page = 1

	page_range = page_list_return(len(paginator.page_range), current_page)		# 返回分页起始页及结束页
	try:
		page_objects = paginator.page(current_page)		# 获取当前页数据
	except (EmptyPage, InvalidPage):
		page_objects = paginator.page(paginator.num_pages)		# 如果有异常则取最后一页的数据

	if current_page >= 5:
		show_first = 1
	else:
		show_first = 0

	if current_page <= int(len(paginator.page_range) - 3):
		show_end = 1
	else:
		show_end = 0

	return post_objects, paginator, page_objects, page_range, current_page, show_first, show_end


def chown(path, user, group=''):
	'''
	设置文件或者目录的所有者
	'''
	if not group:
		group = user

	try:
		uid = pwd.getpwnam(user).pw_uid
		gid = pwd.getpwnam(user).pw_gid
		os.chown(path, uid, gid)
	except KeyError:
		pass


def bash(cmd):
	'''
	执行bash 命令
	'''
	return subprocess.call(cmd, shell=True)


def mkdir(dir_name, username='', mode=755):
	'''
	检查目录是否存在, 不存在就创建目录, 并且权限设置正确
	'''
	cmd = '[ ! -d %s ] && mkdir -p %s && chmod %s %s' % (dir_name, dir_name, mode, dir_name)
	bash(cmd)
	if username:
		chown(dir_name, username)


def my_render(template, data, request):
	return render_to_response(template, data, context_instance=RequestContext(request))


def is_role_request(request, role='user'):
	'''
	要求请求角色正确
	'''
	role_all = {'user': 'CU', 'super': 'SU', 'admin': 'GA'}
	if request.user.role == role_all.get(role, 'CU'):
		return True
	else:
		return False


def set_log(level, filename='jumpserver.org'):
	'''
	写日志到日志文件函数
	'''
	log_file = os.path.join(settings.LOG_DIR, filename)		# 日志文件所在位置
	if not os.path.isfile(log_file):
		os.mknod(log_file)
		os.chmod(log_file, 0777)
	log_level_total = {		# 定义所有日志级别
		'debug': logging.DEBUG,
		'info': logging.INFO,
		'warning': logging.WARN,
		'error': logging.ERROR,
		'critical': logging.CRITICAL
	}
	logger_f = logging.getLogger('jumpserver')		# 创建一个logger对象
	logger_f.setLevel(logging.DEBUG)		# 指定最低日志级别为DEBUG, 低于该级别的日志会忽略
	fh = logging.FileHandler(log_file)		# 指定文件处理程序, 将日志输入到文件
	fh.setLevel(log_level_total.get(level, logging.DEBUG))
	formatter = logging.Formatter('%(asctime)s - %(pathname)s - %(levelname)s - %(message)s')		# 日志文件记录格式
	fh.setFormatter(formatter)
	logger_f.addHandler(fh)
	return logger_f


def require_role(role='user'):
	'''
	要求登录的用户属于某一种角色['SU', 'CU', 'GA']装饰器, 同时也会检测用户是否验证成功
	'''
	def _deco(func):
		def __deco(request, *args, **kwargs):
			request.session['pre_url'] = request.path		# 根据session中间件处理流程, 有会话修改时,会给客户端发送一个cookie session
			if not request.user.is_authenticated():
				return HttpResponseRedirect(reverse('login'))
			if role == 'admin':
				if request.user.role == 'CU':
					return HttpResponseRedirect(reverse('index'))
			elif role == 'super':
				if request.user.role in ['CU', 'GA']:
					return HttpResponseRedirect(reverse('index'))
			return func(request, *args, **kwargs)
		return __deco
	return _deco


def defend_attack(func):
	'''
	自定义防护装饰器,会话有效期内连续登陆超过10次, 将禁止登陆
	'''
	def _deco(request, *args, **kwargs):
		if int(request.session.get('visit', 1)) > 10:
			logger.debug('请求次数: %s' % (request.session.get('visit', 1), ))
			return HttpResponse('Forbidden', status=403)
		request.session['visit'] = request.session.get('visit', 0) + 1		# 修改为默认的0, 否则visit值多加1
		request.session.set_expiry(300)		# 设置会话过期时间为300秒, 300秒内请求次数不能超过10次
		return func(request, *args, **kwargs)
	return _deco


def get_mac_address():
	'''
	返回一个12位的uuid字符
	'''
	node = uuid.getnode()
	mac = uuid.UUID(int=node).hex[-12:]
	return mac


def get_object(model, **kwargs):
	'''
	使用改封装函数查询数据库, 函数参数为模型对象, 过滤条件
	'''
	for value in kwargs.values():
		if not value:
			return None
	the_object = model.objects.filter(**kwargs)		# 从模型里面过滤符合的记录条数, 返回一个QuerySet结果集
	if len(the_object) == 1:
		the_object = the_object[0]
	else:
		the_object = None
	return the_object


class PyCrypt(object):
	'''
	jumpserver 加密类, 封装多种加密函数
	'''
	def __init__(self, key):
		self.key = key		# 原始加密密钥, 长度为16字符
		self.mode = AES.MODE_CBC

	@staticmethod
	def md5_crypt(string):
		'''
		md5非对称加密方法
		'''
		return hashlib.new('md5', string).hexdigest()

	@staticmethod
	def gen_rand_key(length=16, especial=False):
		'''
		默认随机生成16位字符密码
		'''
		salt_key = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
		symbol = '!@$%^&*()_'
		salt_list = []
		if especial:
			for i in range(length-4):
				salt_list.append(random.choice(salt_key))
			for i in range(4):
				salt_list.append(random.choice(symbol))
		else:
			for i in range(length):
				salt_list.append(random.choice(salt_key))
		salt = ''.join(salt_list)
		return salt

	def encrypt(self, passwd=None, length=32):
		'''
		对称加密, 加密生成密码
		'''
		if not passwd:
			passwd = self.gen_rand_key()		# 不指定密码, 随机生成16位字符密码

		cryptor = AES.new(self.key, self.mode, b'8122ca7d906ad5e1')
		try:
			count = len(passwd)
		except TypeError:
			raise ServerError('类型错误')

		add = (length - (count % length))
		passwd += '\0' * add		# 补码, passwd长度需要为length的整数倍
		cipher_text = cryptor.encrypt(passwd)		# 加密后字符
		return b2a_hex(cipher_text)

	def decrypt(self, text):
		'''
		对称加密解密函数, 相同的加密随机数
		'''
		cryptor = AES.new(self.key, self.mode, b'8122ca7d906ad5e1')
		try:
			plain_text = cryptor.decrypt(a2b_hex(text))
		except TypeError:
			raise ServerError(u'解密密码失败!')

		return plain_text.rstrip('\0')


def http_success(request, msg):
	'''
	返回成功页面
	'''
	return render_to_response('success.html', locals())


def http_error(request, msg):
	'''
	返回失败页面
	'''
	message = msg
	return render_to_response('error.html', locals())


CRYPTOR = PyCrypt(settings.KEY)		# KEY 是在部署环境是随机生成的16位字符
logger = set_log(settings.LOG_LEVEL)
