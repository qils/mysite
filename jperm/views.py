#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from __future__ import unicode_literals

import re
from jperm.perm_api import *
from django.db.models import Q
from jperm.utils import trans_all
from django.shortcuts import render
# Create your views here.


@require_role('admin')
def perm_sudo_list(request):
	'''
	sudo 列表视图
	'''
	header_title, path1, path2 = u'Sudo命令', u'别名管理', u'查看别名'
	sudos_list = PermSudo.objects.all()		# 获取所有sudo命令别名

	keyword = request.GET.get('search', '')
	if keyword:
		sudos_list = sudos_list.filter(Q(name=keyword))

	sudos_list, p, sudos, page_range, current_page, show_first, show_end = pages(sudos_list, request)

	return my_render('jperm/perm_sudo_list.html', locals(), request)


@require_role('admin')
def perm_sudo_add(request):
	'''
	添加sudo命令别名视图
	'''
	header_title, path1, path2 = u'Sudo命令', u'别名管理', u'添加别名'
	try:
		if request.method == 'POST':
			name = request.POST.get('sudo_name', '').strip().upper()
			comment = request.POST.get('sudo_comment', '').strip()
			commands = request.POST.get('sudo_commands', '').strip()

			if not name or not commands:
				raise ServerError(u'sudo name 和 commands是必填项!!!')

			deal_space_commands = list_drop_str(re.split(r'[\n,\r]', commands), u'')		# 处理为空的命令, 直接删除空
			deal_all_commands = map(trans_all, deal_space_commands)		# 处理字符为all的命令, 转换为大写
			commands = ', '.join(deal_all_commands)
			logger.debug(u'添加sudo %s: %s' % (name, commands))
			if get_object(PermSudo, name=name):		# 别名重复判断
				error = 'Sudo别名 %s 已经存在' % (name, )
			else:
				sudo = PermSudo(name=name, comment=comment, commands=commands)
				sudo.save()		# 存储到数据库
				msg = u'添加Sudo命令别名: %s 成功' % (name, )
	except ServerError, e:
		error = e

	return my_render('jperm/perm_sudo_add.html', locals(), request)



def perm_sudo_edit(request):
	pass


def perm_sudo_delete(request):
	pass


def perm_role_list(request):
	pass


def perm_role_get(request):
	pass


def perm_role_detail(request):
	pass


def perm_rule_list(request):
	pass


def perm_rule_detail(request):
	pass

