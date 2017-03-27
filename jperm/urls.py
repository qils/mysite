#!/usr/bin/env python
# --*-- conding: utf-8 --*--

from django.conf.urls import patterns, include, url
from jperm.views import *

urlpatterns = patterns(
	'jperm.views',
	url(r'^sudo/list/$', perm_sudo_list, name='sudo_list'),
	url(r'^role/list/$', perm_role_list, name='role_list'),
	url(r'^rule/list/$', perm_rule_list, name='rule_list'),
)
