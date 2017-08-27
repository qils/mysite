#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
from juser.models import AdminGroup
from mysite.api import *
from mysite.settings import BASE_DIR, EMAIL_HOST_USER as MAIL_FROM


def group_add_user(group, user_id=None, username=None):
	'''
	往用户组记录中添加用户
	'''
	if user_id:
		user = get_object(User, id=user_id)
	else:
		user = get_object(User, username=username)

	if user:
		group.user_set.add(user)		# 往用户组中添加用户


def db_add_group(**kwargs):
	'''
	添加一条用户组记录
	'''
	users = kwargs.pop('users_id')		# 去掉在次对用户组是否存在的检查
	group = UserGroup(**kwargs)		# 创建一条用户组记录
	group.save()

	for user_id in users:		# 将选择的用户与添加的用户组关联
		group_add_user(group, user_id)


def db_add_user(**kwargs):
	'''
	给数据库中添加User数据记录
	'''

	groups_post = kwargs.pop('groups')		# 返回所属用户组
	admin_groups = kwargs.pop('admin_groups')		# 管理组, 一个用户只管理一个用户组, 在juser.AdminGroup 模型中定义
	role = kwargs.get('role', 'CU')		# 用户角色, 普通用户, 超级用户, 用户组管理用户
	user = User(**kwargs)		# 在User 表里创建一条用户记录
	user.set_password(kwargs.get('password'))		# 修改User密码
	user.save()		# 保存记录

	if groups_post:		# 创建用户时是否指定该用户属于哪个用户组, 如果有则将所属组增加到用户记录
		group_list = []
		for group_id in groups_post:
			group = UserGroup.objects.filter(id=group_id)		# 过滤用户组
			group_list.extend(group)
		user.group = group_list		# 增加用户组, 多对多字段能在记录创建后在调整
		user.save()

	if admin_groups and role == 'GA':		# 如果是组管理员, 需要添加组管理员和组到管理组中, 一个组管理员能关联到多个用户组
		for group_id in admin_groups:
			group_object = get_object(UserGroup, id=group_id)
			if group_object:
				AdminGroup(user=user, group=group_object).save()
	return user		# 返回添加的user对象


def gen_ssh_key(username, password='', key_dir=os.path.join(settings.KEY_DIR, 'user'), authorized_keys=True, home='/home', length=2048):
	'''
	生成一个用户的ssh秘钥对
	'''
	logger.debug(u'生成%s用户ssh key, 并设置authorized_keys' % (username, ))
	private_key_file = os.path.join(key_dir, username + '.pem')		# 根据每个用户名创建私钥文件
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
		chown(authorized_key_file, username)		# 设置文件的所属用户, 用户组


def server_add_user(username, ssh_key_pwd=''):
	'''
	在服务器上创建一个主机用户
	'''
	bash("useradd '%s'" % (username, ))		# 这里如果指定授权用户登录shell时会导致一个问题： 使用秘钥验证没法通过
	bash('echo "if [ -f /data/djcode/mysite/init.sh ];then" >> /home/%s/.bash_profile' % (username, ))		# 改用在每个授权的 .bash_profile文件中添加登录执行脚本
        bash('echo "    source /data/venv/bin/activate" >> /home/%s/.bash_profile' % (username, ))
	bash('echo "    /bin/sh /data/djcode/mysite/init.sh" >> /home/%s/.bash_profile' % (username, ))
	bash('echo "fi" >> /home/%s/.bash_profile' % (username, ))
	gen_ssh_key(username, ssh_key_pwd)		# 创建用户的ssh key


def db_del_user(username):
	'''
	从User表中删除用户
	'''
	user = get_object(User, username=username)
	if user:
		user.delete()


def server_del_user(username):
	'''
	从服务器上删除一个跳板机服务器上的系统用户
	'''
	bash('userdel -f -r %s' % (username, ))		# 删除系统用户命令
	logger.debug('rm -f %s/%s_*.pem' % (os.path.join(settings.KEY_DIR, 'user'), username))		# 记录删除日志
	private_key_file = os.path.join(settings.KEY_DIR, 'user', username + '.pem')
	if os.path.isfile(private_key_file):
		os.unlink(private_key_file)		# 删除用户ssh key 文件


def user_add_mail(user, kwargs):
	'''
	给添加的用户发送邮件
	'''
	user_role = {'SU': u'超级管理员', 'CU': u'普通用户', 'GA': u'组管理员'}
	mail_title = u'恭喜你的跳板机用户 %s 添加成功' % (user.name, )		# 设置邮件主题
	mail_msg = u'''
	Hi, %s
		你的用户名: %s
		你的权限: %s
		你的web登录密码: %s
		你的ssh秘钥文件密码: %s
		秘钥下载地址: %s/juser/key/down/?uuid=%s
		说明: 请登录跳板机后台下载秘钥, 然后使用秘钥登录跳板机!
	''' % (user.name, user.username, user_role.get(user.role, u'普通用户'), kwargs.get('password'), kwargs.get('ssh_key_pwd'), settings.URL, user.uuid)
	try:
		send_mail(mail_title, mail_msg, MAIL_FROM, [user.email], fail_silently=False)
	except Exception, e:
		logger.debug('%s' % (e, ))


def get_display_msg(user, password='', ssh_key_pwd='', send_mail_need=False):
	if send_mail_need:
		msg = u'添加用户 %s 成功! 用户名, 密码已发送到 %s 邮箱!!!' % (user.name, user.email)
	else:
		msg = u'''
		跳板机地址: %s </br>
		用户名: %s </br>
		密码: %s </br>
		密钥密码: %s </br>
		密钥下载URL: %s/juser/key/down/?uuid=%s </br>
		该账号可以登录web和跳板机
		''' % (settings.URL, user.username, password, ssh_key_pwd, settings.URL, user.uuid)
	return msg


def db_update_user(**kwargs):
	'''
	用户信息数据库更新
	'''
	groups_post = kwargs.pop('groups')		# 新提交的用户组ID
	admin_groups_post = kwargs.pop('admin_groups')
	user_id = kwargs.pop('user_id')
	user = User.objects.filter(id=user_id)
	if user:
		user_get = user[0]
		password = kwargs.pop('password')		# 取出密码
		user.update(**kwargs)		# 更新数据
		if password.strip():		# 密码不为空时, 才更新密码
			user_get.set_password(password)
			user_get.save()
	else:
		return None

	group_select = []		# 定义一个空列表, 用来保存用户组记录
	if groups_post:
		for group_id in groups_post:
			group = UserGroup.objects.filter(id=group_id)
			group_select.extend(group)
	user_get.group = group_select		# 更新用户添加的组信息

	if admin_groups_post:
		user_get.admingroup_set.all().delete()
		for admin_group_id in admin_groups_post:
			group = get_object(UserGroup, id=admin_group_id)
			AdminGroup(user=user_get, group=group).save()
