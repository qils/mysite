#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
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


def gen_ssh_key(username, password='', key_dir=os.path.join(settings.KEY_DIR, 'user'), authorized_keys=True, home='/home', length=2048):
	'''
	生成一个用户的ssh秘钥对
	'''
	logger.debug('生成ssh key, 并设置authorized_keys')
	private_key_file = os.path.join(key_dir, username + '.pem')
	mkdir(key_dir, mode=777)
	if os.path.isfile(private_key_file):
		os.unlink(private_key_file)		# 文件存在首先删除文件
	ret = bash('echo -e "y\n" | ssh-keygen -t rsa -f %s -b %s -P "%s"' % (private_key_file, length, password))

	if authorized_keys:
		auth_key_dir = os.path.join(home, username, '.ssh')
		mkdir(auth_key_dir, username=username, mode=700)
		authorized_key_file = os.path.join(auth_key_dir, 'authorized_keys')
		with open(private_key_file + '.pub') as pub_f:
			with open(authorized_key_file, 'w') as auth_f:
				auth_f.write(pub_f.read())
		os.chmod(authorized_key_file, 0600)
		chown(authorized_key_file, username)