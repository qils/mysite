#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django import template
from mysite.api import *

register = template.Library()		# 扩展模板系统的全局变量


@register.filter(name='to_avatar')		# 自定义过滤器
def to_avatar(role_id='0'):
	'''
	不同角色使用不同的图片
	'''
	role_dict = {'0': 'user', '1': 'admin', '2': 'root'}
	return role_dict.get(str(role_id), 'user')


@register.filter(name='to_name')
def to_name(user_id):
	'''
	依据user_id,获取用户名称
	'''
	try:
		user = User.objects.filter(id=int(user_id))
		if user:
			user = user[0]
			return user.name
		else:
			return '非法用户'
	except:
		return '非法用户'


@register.filter(name='get_role')
def get_role(user_id):
	user_role = {'SU': '超级管理员', 'GA': '组管理员', 'CU': '普通用户'}
	user = get_object(User, id=user_id)
	if user:
		return user_role.get(str(user.role), '普通用户')
	else:
		return '普通用户'


@register.filter(name='bool2str')
def bool2str(value):
	if value:
		return '是'
	else:
		return '否'