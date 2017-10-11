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
from django.db.models import Q

# Create your views here.


@require_role(role='admin')
def log_list(request, offset):		# URL中捕获的参数值, 传递给视图函数
	'''
	日志审计视图
	'''
	header_title, path1 = u'审计', u'操作审计'
	date_seven_day = request.GET.get('start', '')
	date_now_str = request.GET.get('end', '')
	username_list = request.GET.getlist('username', [])
	host_list = request.GET.getlist('host', [])
	cmd = request.GET.get('cmd', '')

	if offset == 'online':
		keyword = request.GET.get('keyword', '')
		posts = Log.objects.filter(is_finished=False).order_by('-start_time')		# 过滤在线的所有登录日志
		if keyword:
			posts = posts.filter(Q(user__icontains=keyword) | Q(host__icontains=keyword) | Q(login_type=keyword))

	contact_list, p, contacts, page_range, current_range, show_first, show_end = pages(posts, request)
	session_id = request.session.session_key

	return my_render('jlog/log_%s.html' % (offset, ), locals(), request)


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

		# while os.path.isfile(filepath):		# 暂时没发现该判断有什么作用
			# filename = str(uuid.uuid4())
			# filepath = os.path.join(path, 'tty', date, filename + '.zip')
		password = str(uuid.uuid4())		# 设置ZIP文件密码

		try:
			zf = zipfile.ZipFile(filepath, 'w', zipfile.ZIP_DEFLATED)
			zf.setpassword(password)		# 设置密码
			zf.writestr(filename, json.dumps(self.log))
			zf.close()
			record = TermLog.objects.create(
				logPath=filepath,
				logPWD=password,
				filename=filename,
				history=json.dumps(self.CMD),
				timestamp=int(self.recoderStartTime)
			)

			if self.user:
				record.user.add(self.user)
		except:
			record = TermLog.objects.create(
				logPath='locale',
				logPWD=password,
				log=json.dumps(self.log),
				filename=filename,
				history=json.dumps(self.CMD),
				timestamp=int(self.recoderStartTime)
			)

			if self.user:
				record.user.add(self.user)

		try:
			del TermLogRecorder.loglist[str(self.id)]
		except KeyError:
			pass