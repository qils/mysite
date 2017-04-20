#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
from django import template
from mysite.api import *
from jperm.perm_api import get_group_user_perm

register = template.Library()		# 扩展模板系统的全局变量


@register.filter(name='members_count')
def members_count(group_id):
	'''
	统计一个用户组里面所有用户的总数
	'''
	group = get_object(UserGroup, id=group_id)
	if group:
		return group.user_set.count()
	else:
		return 0


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
		return '<b class="btn btn-xs btn-info">是</b>'
	else:
		return '<b class="btn btn-xs btn-danger">否</b>'


@register.filter(name='groups2str')
def groups2str(group_list):
	'''
	用户组列表转换为str
	'''
	if len(group_list) < 3:
		return '|'.join([group.name for group in group_list])
	else:
		return '%s ...' % ('|'.join([group.name for group in group_list[0:2]]))


@register.filter(name='user_perm_asset_num')
def user_perm_asset_num(user_id):
	user = get_object(User, id=user_id)
	if user:
		user_perm_info = get_group_user_perm(user)
		return len(user_perm_info.get('asset').keys())
	else:
		return 0


@register.filter(name='key_exist')
def key_exist(username):
	'''
	用户的ssh key 是否存在
	'''
	if os.path.isfile(os.path.join(settings.KEY_DIR, 'user', username + '.pem')):
		return True
	else:
		return False


@register.filter(name='int2str')
def int2str(value):
	'''
	int 转为 str
	'''
	return str(value)
