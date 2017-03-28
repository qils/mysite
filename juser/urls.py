#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.conf.urls import patterns, include, url
from juser.views import *


urlpatterns = patterns(
	'juser.views',
	url(r'^password/forget/$', 'forget_password', name='password_forget'),
	url(r'^password/reset/$', 'reset_password', name='password_reset'),
	url(r'^group/list/$', 'group_list', name='user_group_list'),
	url(r'^user/list/$', 'user_list', name='user_list'),
	url(r'^user/detail/$', 'user_detail', name='user_detail'),
	url(r'^user/profile/$', 'profile', name='user_profile'),
	url(r'^user/update/$', 'change_info', name='user_update'),
)
