import apamax.log_analyzer
import io
import sys
import time
import logging
import os

log = logging.getLogger('test')

durationSecs = float(sys.argv[1])
mode = sys.argv[2]
analyzerArgs = sys.argv[3:]

with open('fake-correlator.log', 'w') as f:
	pass

# monkey-patch io.open to allow us to fake the input/output without generating huge files on disk
origopen = io.open
class FakeLogFile(io.TextIOBase):
	def __init__(self):
		self.linenum = 0
		self.statuslines = 0
		self.buffer = [] # allow a single readline
	
	def generateLogLine(self):
		self.linenum = i = self.linenum+1

		
		timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(1546398245 + self.linenum))+'.123'
		
		# initialize for TypicalMix_StatusEvery3Lines
		warn_error_msg_period = 100 # add a warn and an error every 100 lines
		status_line_period = 3
		
		if mode != 'OnlyIgnoredLines':
		
			if mode == 'OnlyWarnErrorLines':
				warn_error_msg_period = 3+1
				status_line_period = None
			if mode == 'OnlyStatusLines':
				warn_error_msg_period = None
				status_line_period = 1
				
			if warn_error_msg_period:
				if i % warn_error_msg_period == 0:
					return f"{timestamp} 14:04:17.495 WARN [140084627105536{i}] - <plugins.JmsPlugin> Got an unexpected warning: java.lang.RuntimeException: Failed to process Correlator-JMS control event 'com.apama.correlator.jms.__ReceiverAcknowledgeAndResume(\"WebSphere_MQ-receiver-queue-myq\")': Cannot resume receiver which is already resumed: 'MyQ'"
				if i % warn_error_msg_period == 1:
					return f"{timestamp} 14:04:17.495 ERROR [140084627105536{i}] - <plugins.JmsPlugin> Got an unexpected error: java.lang.RuntimeException: Failed to process Correlator-JMS control event 'com.apama.correlator.jms.__ReceiverAcknowledgeAndResume(\"WebSphere_MQ-receiver-queue-myq\")': Cannot resume receiver which is already resumed: 'MyQ' - stack trace is:"
				if i % warn_error_msg_period == 2: # multi-line error message
					return f" 	at com.apama.foo()"
				if i % warn_error_msg_period == 3:
					return f" 	at com.apama.bar()"
			
			if status_line_period and (i % status_line_period == 0):
				self.statuslines += 1
				lcn = '<none>' if i%2==0 else '"my context"'
				return f'{timestamp} INFO  [22872] - Correlator Status: sm=1 nctx=2 ls=3 rq=4 lcn={lcn} lct=5.5 si=0.0 so=1.1 jvm={7000+i*100} rx={i*10} tx={i*20} mynewstatus=10 rt=0 nc=0 vm=3 pm=4 runq=0'

		# the rest of the file is some random info log messages which we will ignore
		return f'{timestamp} INFO  [22872] - com.acme.myackage.MyServiceMonitor [123] This is a message from a service monitor indicating that we\'re processing event MyThingHappened("1231111111111", 123, 456, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx {i}")'
	
		return f'{timestamp} INFO  [22872] - Correlator Status: sm=1 nctx=2 ls=3 rq=4 lcn=<none> lct=5.5 si=6.6 so=1.1 jvm=7168 rx=8 tx=9 mynewstatus=10 rt=0 nc=0 vm=3 pm=4 runq=0  somethingelse=123'
		
	
	def readline(self, size=-1):
		l = self.generateLogLine()
		i = self.linenum
		if i < 200:
			# write out the first few so we know what it looks like
			sys.stdout.write(l+'\n')
			return l
		if i == 200:
			# start timing
			self.starttime = time.perf_counter()
		if i%10000 == 0:
			timenow = time.perf_counter()
			if timenow-self.starttime > durationSecs:
				elapsed = timenow-self.starttime
				log.info(f'Completed performance test: {int(i/ elapsed)} total lines/second, {int(self.statuslines/ elapsed)} status lines/second, {5*self.statuslines/elapsed/60.0/60.0:0.3} log hours per second, duration: {elapsed} seconds')
				# don't bother measuring the one-off end of file costs
				return ''
		
		return l
	
	def write(self, *args, **kwargs):
		pass # no-op

def fakeopen(file, mode='r', **kwargs):
	if (file.endswith('.log') and 'r' in mode):
		return FakeLogFile()

	# skip the O(n) big output file, since we don't want to be generating huge files
	if os.path.basename(file) == 'status_fake-correlator.csv':
		return FakeLogFile()

	return origopen(file, mode, **kwargs)
io.open = fakeopen

tool = apamax.log_analyzer.LogAnalyzerTool()
tool.main([
	'fake-correlator.log'
	]+analyzerArgs)
