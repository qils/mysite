#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import uuid
import logging
from mysite import settings
from django.http import HttpResponse
from juser.models import User, UserGroup
from django.core.urlresolvers import reverse


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
	formatter = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - %(message)s')		# 日志文件记录格式
	fh.setFormatter(formatter)
	logger_f.addHandler(fh)
	return logger_f


def require_role(role='user'):
	pass


def defend_attack(func):
	'''
	自定义防护装饰器,会话有效期内连续登陆超过10次, 将禁止登陆
	'''
	def _deco(request, *args, **kwargs):
		if int(request.session.get('visit', 1)) > 10:
			logger.debug('请求次数: %s' % (request.session.get('visit', 1), ))
			return HttpResponse('Forbidden', status=403)
		request.session['visit'] = request.session.get('visit', 1) + 1
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


logger = set_log(settings.LOG_LEVEL)
