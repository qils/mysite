#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import re
import time
import pyte
from mysite.api import *
from django.shortcuts import render

# Create your views here.


def log_list(request, offset):
	pass


class TermLogRecorder(object):
	loglist = dict()

	def __init__(self, user=None, uid=None):
		self.log = {}
		self.id = 0
		if isinstance(user, User):
			self.user = user		# User 对象
		elif uid:
			self.user = User.objects.get(id=uid)
		else:
			self.user = None

		self.recoderStartTime = time.time()		# 开始记录时间戳
		self.__init_screen_stream()
		self.recoder = False
		self.commands = []
		self._lists = None
		self.file = None
		self.filename = None
		self._data = None
		self.vim_pattern = re.compile(r'\W?vi[m]?\s.* | \W?fg\s.*', re.X)
		self._in_vim = False
		self.CMD = {}

	def __init_screen_stream(self):
		'''
		初始化虚拟屏幕和字符流
		'''
		self._stream = pyte.ByteStream()
		self._screen = pyte.Screen(100, 35)
		self._stream.attach(self._screen)

	def setid(self, id):
		self.id = id
		TermLogRecorder.loglist[str(id)] = [self]

	def write(self, msg):
		try:
			self.write_message(msg)
		except:
			pass

		self.log[str(time.time() - self.recoderStartTime)] = msg.decode('utf-8', 'replace')