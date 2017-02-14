#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from juser.models import AdminGroup
from mysite.api import *


def db_add_user(**kwargs):
	'''
	给数据库中添加数据
	'''

	groups_post = kwargs.pop('groups')		# 返回所属用户组
	admin_groups = kwargs.pop('admin_groups')		# 管理组, 一个用户只管理一个用户组, 在juser.AdminGroup 模型中定义
	role = kwargs.get('role', 'CU')		# 用户角色, 普通用户, 超级用户, 用户组管理用户
	user = User(**kwargs)		# 在User 表里创建一条用户记录
	user.set_password(kwargs.get('password'))		# 修改User密码
	user.save()

	if groups_post:		# 创建用户时是否指定该用户属于哪个用户组, 如果有则将所属组增加到用户记录
		group_list = []
		for group_id in groups_post:
			group = UserGroup.objects.filter(id=group_id)		# 过滤用户组
			group_list.extend(group)
		user.group = group_list		# 增加用户组, 多对多字段能在记录创建后在调整
		user.save()

	if admin_groups and role == 'GA':		# 如果是组管理员, 需要添加组管理员和组到管理组中
		for group_id in admin_groups:
			group_object = get_object(UserGroup, id=group_id)
			if group_object:
				AdminGroup(user=user, group=group_object).save()
	return user