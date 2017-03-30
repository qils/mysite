#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from juser.models import User
from jasset.models import Asset

'''
定义上下文处理器, 当使用context=RequestContext(request)渲染模板时, 函数返回的context将会传送到模板中
'''


def name_proc(request):
	user_id = request.user.id
	role_id = {'SU': 2, 'GA': 1, 'CU': 0}.get(request.user.role, 0)
	user_total_num = User.objects.all().count()		# 所有用户数
	user_active_num = User.objects.filter(is_active=True).count()		# 所有激活用户数
	host_total_num = Asset.objects.all().count()		# 所有资产数
	host_active_num = Asset.objects.filter(is_active=True).count()		# 所有激活资产数
	request.session.set_expiry(3600)

	info_dic = {
		'session_user_id': user_id,
		'session_role_id': role_id,
		'user_total_num': user_total_num,
		'user_active_num': user_active_num,
		'host_total_num': host_total_num,
		'host_active_num': host_active_num,
	}
	return info_dic