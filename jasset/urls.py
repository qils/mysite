#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.conf.urls import patterns, include, url
from jasset.views import *

urlpatterns = patterns(
    '',
    url(r'^group/list/$', group_list, name='asset_group_list'),
    url(r'^asset/list/$', asset_list, name='asset_list'),
    url(r'^idc/list/$', idc_list, name='idc_list'),
)
