#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import re
import ast
import time
import pyte
import json
import zipfile

from mysite.api import *
from mysite import settings
from django.shortcuts import render
from django.http import HttpResponseNotFound
from django.db.models import Q

# Create your views here.


@require_role(role='admin')
def log_list(request, offset):		# URL中捕获的参数值, 传递给视图函数
	'''
	日志审计视图
	'''
	path1, path2 = u'审计', u'操作审计'
	date_seven_day = request.GET.get('start', '')		# 从表单提交, 开始时间
	date_now_str = request.GET.get('end', '')		# 从表单提交, 结束时间
	username_list = request.GET.getlist('username', [])		# 从表单提交, 查询username
	host_list = request.GET.getlist('host', [])		# 从表单提交, 查询主机名
	cmd = request.GET.get('cmd', '')		# 从表单提交, 查询命令

	if offset == 'online':		# 在线统计
		keyword = request.GET.get('keyword', '')
		posts = Log.objects.filter(is_finished=False).order_by('-start_time')		# 过滤在线的所有登录日志
		if keyword:
			posts = posts.filter(Q(user__icontains=keyword) | Q(host__icontains=keyword) | Q(login_type=keyword))
	elif offset == 'exec':		# 批量执行命令统计
		posts = ExecLog.objects.all().order_by('-id')
		keyword = request.GET.get('keyword', '')
		if keyword:
			posts = posts.filter(Q(user__icontains=keyword) | Q(host__icontains=keyword) | Q(cmd__contains=keyword))
	elif offset == 'file':		# 批量文件执行统计
		keyword = request.GET.get('keyword', '')
		posts = FileLog.objects.all().order_by('-id')
		if keyword:
			posts = posts.filter(Q(user__icontains=keyword) | Q(host__icontains=keyword) | Q(filename__icontains=keyword))
	else:
		posts = Log.objects.filter(is_finished=True)		# 过滤已经退出的登录记录
		username_all = set([log.user for log in Log.objects.all()])		# 过滤所有登录的用户
		ip_all = set([log.host for log in Log.objects.all()])		# 过滤所有登录的主机

		if date_seven_day and date_now_str:
			start_time = datetime.datetime.strptime(date_seven_day + ' 00:00:01', '%m/%d/%Y %H:%M:%S')
			end_time = datetime.datetime.strptime(date_now_str + ' 23:59:59', '%m/%d/%Y %H:%M:%S')
			posts = posts.filter(start_time__gte=start_time).filter(end_time__lt=end_time)

		if username_list:
			posts = posts.filter(username__in=username_list)

		if host_list:
			posts = posts.filter(host__in=host_list)

		logger.debug(posts.count())
		if cmd:
			cmd_list = TtyLog.objects.filter(cmd__icontains=cmd)
			logger.debug(cmd_list.count())
			posts = posts.filter(id__in=set([cmd_log.log_id for cmd_log in cmd_list]))

		if not date_seven_day:
			date_now = datetime.datetime.now()
			date_now_str = date_now.strftime('%m/%d/%Y')		# 当前时间
			date_seven_day = (datetime.datetime.now() + datetime.timedelta(days=-7)).strftime('%m/%d/%Y')		# 七天前时间

	contact_list, p, contacts, page_range, current_range, show_first, show_end = pages(posts, request)
	session_id = request.session.session_key		# 获取session key

	return my_render('jlog/log_%s.html' % (offset, ), locals(), request)


@require_role(role='admin')
def log_history(request):
	'''
	用户命令执行日志
	'''
	id = request.GET.get('id')
	log = get_object(Log, id=id)

	if log:
		content = ''
		tty_logs = log.ttylog_set.all()		# 反向选择登录用户执行的所有命令
		for tty_log in tty_logs:
			content += '%s: %s\n' % (tty_log.datetime.strftime('%Y-%m-%d %H:%M:%S'), tty_log.cmd)
	else:
		content = u'无日志记录'

	return HttpResponse(content)


@require_role(role='admin')
def log_detail(request, offset):
	'''
	日志详细记录视图
	'''
	id = request.GET.get('id', '')
	if offset == 'exec':
		log = ExecLog.objects.get(id=id)
		assets_hostname = [hostname for hostname in ast.literal_eval(log.host) if hostname]
		return my_render('jlog/exec_detail.html', locals(), request)
	elif offset == 'file':
		log = FileLog.objects.get(id=id)
		file_list = log.filename.split(' ')
		assets_hostname = [hostname for hostname in ast.literal_eval(log.host) if hostname]
		return my_render('jlog/file_detail.html', locals(), request)


@require_role(role='admin')
def log_kill(request):
	'''
	管理员结束连接进程
	'''
	pid = request.GET.get('id')		# 获取提交的进程pid
	log = Log.objects.filter(pid=pid)
	if log:
		log = log[0]
		try:
			os.kill(int(pid), 9)		# 结束进程
		except Exception:
			pass

		Log.objects.filter(pid=pid).update(is_finished=True, end_time=datetime.datetime.now())		# 手动更新
		return my_render('jlog/log_offline.html', locals(), request)
	else:
		return HttpResponseNotFound(u'没有此进程')


def log_record(request):
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