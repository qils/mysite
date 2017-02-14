#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import uuid
from juser.models import User, UserGroup


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
