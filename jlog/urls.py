#!/usr/bin/env python
# --*-- coding: utf-8 --*--


from django.conf.urls import patterns, include, url
from jlog.views import *

urlpatterns = patterns(
	'',
	url(r'^list/(\w+)/$', log_list, name='log_list'),
)
