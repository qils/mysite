#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from __future__ import unicode_literals
from jperm.perm_api import *
from django.db.models import Q
from django.shortcuts import render
# Create your views here.


@require_role('admin')
def perm_sudo_list(request):
	'''
	'''
	header_title, path1, path2 = 'Sudo命令', '别名管理', '查看别名'
	sudos_list = PermSudo.objects.all()		# 获取所有sudo命令别名

	keyword = request.GET.get('search', '')
	if keyword:
		sudos_list = sudos_list.filter(Q(name=keyword))

	sudos_list, p, sudos, page_range, current_page, show_first, show_end = pages(sudos_list, request)

	return my_render('jperm/perm_sudo_list.html', locals(), request)


def perm_sudo_add(request):
	pass


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

