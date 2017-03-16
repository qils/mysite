#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import uuid
import logging
import hashlib
from mysite import settings
from django.http import HttpResponse, HttpResponseRedirect
from juser.models import User, UserGroup
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.shortcuts import render_to_response


def is_role_request(request, role='user'):
	'''
	要求请求角色正确
	'''
	role_all = {'user': 'CU', 'super': 'SU', 'admin': 'GA'}
	if request.user.role == role_all.get(role, 'user'):
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
	formatter = logging.Formatter('%(asctime)s - %(pathname)s/%(filename)s - %(levelname)s - %(message)s')		# 日志文件记录格式
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
		request.session.set_expiry(300)		# 设置会话过期时间为300秒
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
	@staticmethod
	def md5_crypt(string):
		'''
		md5非对称加密方法
		'''
		return hashlib.new('md5', string).hexdigest()


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

logger = set_log(settings.LOG_LEVEL)
