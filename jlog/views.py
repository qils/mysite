#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import re
import time
import pyte
import json
import zipfile

from mysite.api import *
from mysite import settings
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

		self.recoderStartTime = time.time()		# 开始时间戳
		self.__init_screen_stream()
		self.recoder = False
		self.commands = []
		self._lists = None
		self.file = None
		self.filename = None
		self._data = None
		self.vim_pattern = re.compile(r'\W?vi[m]?\s.* | \W?fg\s.*', re.X)		# re.X 模式能忽略一些空格, 以及注释后面的所有字符
		self._in_vim = False
		self.CMD = {}

	def _command(self):
		for i in self._screen.display:
			if i.strip().__len__() > 0:
				self.commands.append(i.strip())
				if not i.strip() == '':
					self.CMD[str(time.time())] = self.commands[-1]
		logger.debug(self.commands)
		logger.debug(self.CMD)
		self._screen.reset()

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
		if self.recoder and not self._in_vim:
			if self.commands.__len__() == 0:
				self._stream.feed(msg)
			elif not self.vim_pattern.search(self.commands[-1]):
				pass
			else:
				pass
		else:
			if self._in_vim:
				pass
			else:
				self._command()

		try:
			self.write_message(msg)
		except:
			pass

		self.log[str(time.time() - self.recoderStartTime)] = msg.decode('utf-8', 'replace')

	def save(self, path=settings.LOG_DIR):
		date = datetime.datetime.now().strftime('%Y%m%d')		# 纪录日志时间: 年, 月, 日
		filename = str(uuid.uuid4())
		self.filename = filename
		filepath = os.path.join(path, 'tty', date, filename + '.zip')

		if not os.path.isdir(os.path.dirname(filepath)):
			mkdir(os.path.dirname(filepath), mode=777)

		# while True:		# 暂时没发现该判断有什么作用
			# filename = str(uuid.uuid4())
			# filepath = os.path.join(path, 'tty', date, filename + '.zip')
		password = str(uuid.uuid4())		# 设置ZIP文件密码

		try:
			zf = zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED)
			zf.setpassword(password)		# 设置密码
			zf.writestr(filename, json.dumps(self.log))
			zf.close()
		except:
			pass
