#!/usr/bin/env python3

""" This is a script for analyzing Apama correlator log files. 

It extracts and summarizes information from status lines and other 
log messages. 
"""

__version__ = '3.0.dev'
__date__ = '2019-09-24'
__author__ = "Ben Spiller"
__license__ = "Apache"

import logging, os, io, argparse, re, time, sys, collections, datetime, calendar
import json
import glob

log = logging.getLogger('loganalyzer')

COLUMN_DISPLAY_NAMES = collections.OrderedDict([
	# timing
	('datetime', 'datetime'), # date time string
	('seconds', 'seconds'), # epoch time in seconds, in case people want to calculate rates. Currently this is in local time not UTC
	('line num', 'line num'),

	# queues first
	('iq','iq=queued input'), # executors queued
	('icq','icq=queued input public'),
	('oq','oq=queued output'),
	('rq','rq=queued route'),
	('runq','runq=queued ctxs'),

	('nc','nc=ext+int consumers'),
	
	# rx/tx
	('=rx /sec','rx /sec'),
	('=tx /sec','tx /sec'),
	('=rt /sec','rt /sec'),

	('rx','rx=received'),
	('tx','tx=sent'),
	('rt','rt=routed'),
	
	# things that take memory
	('sm','sm=monitor instances'),
	('nctx','nctx=contexts'),
	('ls','ls=listeners'),

	('pm','pm=resident MB'), # convert to MB as easier to read than kb values
	('vm','vm=virtual MB'),
	('jvm','jvm=Java MB'), # cf JMS
	
	('=pm delta MB', None),
	('=vm delta MB', None),
	('=jvm delta MB', None),

	# swapping
	('si','si=swap pages read /sec'),
	('so','so=swap pages written /sec'),
	('=is swapping', None), # 1 if swapping, 0 if not; use integer not bool so we can graph it and sum it
	
	# log messages
	('=errors /sec',None),
	('=warns /sec',None),
	('=log lines /sec',None),
	
	# slow contexts and consumers (some of these are strings, so put them at the end)
	('lcn','lcn=slowest ctx'), # name
	('lcq','lcq=slowest ctx input queue'),
	('lct','lct=slowest ctx latency secs'),

	('srn','srn=slowest consumer/plugin'), # name
	('srq','srq=slowest consumer/plugin queue'), 
])
"""Contains an entry for each key whose name will be changed, and defines the default column order. 
Units are included where possible (which may differ from the logged units)
If value is None, column will be ignored. Is key started with ":", it's a generated field. 
Items listed here but not in the status line will be ignored; 
Extra items in status line but not here will be added.

Use | chars to break up sections of related columns
"""


class UserError(Exception):
	""" Indicates an exception that should be display to the user without a stack trace. """
	pass

################################################################################
#
# Line parsing

class LogLine(object):
	"""
	Utility class for efficiently parsing a log line. The following fields are always set:
	
	lineno - the integer line number within the log file
	line - the full log line (with trailing whitespace stripped); never an empty string
	message - the (unicode character) string message (after the first " - " if a normal line, or else the same as the line if not)
	level - the first character of the log level (upper case), e.g. "I" for info, "E" for error, "#" for force. None if not a normal log line. 
	
	It is possible to get the timestamp, level and other details by calling getDetails
	"""
	LINE_REGEX = re.compile(r'(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d[.]\d\d\d) ([A-Z]+) +\[([^\]]+)\] -( <[^>]+>)? (.*)')
	
	__slots__ = ['line', 'lineno', 'message', 'level', '__details', '__rawdetails'] # be memory-efficient
	def __init__(self, line, lineno):
		self.line = line
		self.lineno = lineno
		self.__details = None

		firstchar = line[0]
		
		# if it's an apama-ctrl file, pre-process the line
		isapamactrl = False
		if firstchar == '[': # probably apama ctrl
			iscorrelator = line.startswith(  '[correlator]  ')
			if not iscorrelator:
				isapamactrl = line.startswith('[apama-ctrl]  ')
			if iscorrelator or isapamactrl:
				self.line = line = line[14:]
				if len(line)>0: firstchar = line[0]

		# do minimal parsing by default to keep speed high for messages we don't care about - just separate message from prefix
		i = line.find(' - ')
		if i >= 0 and firstchar.isdigit(): # if it looks like a log line
			self.message = line[i+3:]
			if isapamactrl:
				self.message = f'<apama-ctrl> {self.message}'
			try:
				self.level = line[24] # this is a nice efficient way to get the log level without slow regexes
			except IndexError: # just in case it's not a normal log line (though we hope the firstchar.isdigit() check will catch most of those)
				self.level = None
			self.__rawdetails = line[:i]
		else:
			self.message = line
			self.level = None
			self.__rawdetails = None
	
	def getDetails(self):
		"""
		Returns a dictionary containing: datetimestring, thread, logcategory
		
		The result is cached, as getting this data is a bit time-consuming; avoid unless you're sure you need it. 
		"""
	
		det = self.__details
		if det is not None: return det
		if self.__rawdetails is not None: 
			m = LogLine.LINE_REGEX.match(self.line)
			if m:
				g = m.groups()
				self.__details = {
					'datetimestring':g[0],
					'thread':g[2],
					'logcategory':g[3].strip() if g[3] else '',
				}
				self.message = g[4]
				return self.__details

		self.__details = {
					'datetimestring':'',
					'thread':'',
					'logcategory':'',
				}
		return self.__details
	
	def getDateTime(self):
		"""
		Parse the datetime object from this log line. Don't do this unless you need it.  
		"""
		det = self.getDetails()
		if 'datetime' in det:
			return det['datetime']
			
		d = datetime.datetime.strptime(self.getDetails()['datetimestring'], '%Y-%m-%d %H:%M:%S.%f')
		# rather than using timezone of current machine which may not match origin, convert to utc
		d = d.replace(tzinfo=datetime.timezone.utc) 
		det['datetime'] = d
		return d

	
	def __repr__(self): return '#%d: %s'%(self.lineno, self.line)

################################################################################
#
# Writers

class BaseWriter(object):
	"""
	Base class for something that writes to a single file, and writes output to file(s). 
	
	Caller must call closeFile when it's no longer needed. 
	"""
	def __init__(self, manager, **kwargs):
		self.manager = manager
		self.output = None
		assert not kwargs, kwargs # reserved for future use

	def createFile(self, filename):
		"""
		Open a new text file in the output dir, stored as self.output. 
		
		Automatically closed on shutdown. 
		
		Any existing file is closed. 
		
		@param filename: The base filename, e.g. 'warnings_@LOG_NAME@.txt', 
		with @LOG_NAME@ replaced by the identifier for the current corelator instancelog file. 
		@param includeLogFilePrefix: True if this output is per-input log file, 
		in which case it will be added as a prefix
		"""
		self.closeFile()
		
		assert filename
		assert not os.path.isabs(filename), filename
		filename = filename.replace('@LOG_NAME@', self.manager.currentname)
		
		self.output = io.open(os.path.join(self.manager.outputdir, filename), 'w', encoding='utf-8')
		return self.output

	def _writeFooter(self):
		"""
		Called once just before file is closed.
		"""
		pass

	def closeFile(self):
		if self.output is not None:
			self._writeFooter()
			self.output.close()
			self.output = None

class CSVStatusWriter(BaseWriter):
	output_file = 'status_@LOG_NAME@.csv'

	def writeHeader(self, columns=None, extraInfo=None, **extra):
		self.output = self.createFile(self.output_file)
		self.columns = columns
		items = list(columns)
		items[0] = '# '+items[0]
		if extraInfo:
			items.append('# metadata: ')
			
			# this is a relatively CSV-friendly way of putting extra metadata into the file without messing with the main columns
			items.extend(['%s=%s'%(k, extraInfo[k]) for k in extraInfo])
		self.writeCSVLine(items)
		
	def writeStatus(self, status=None, **extra):
		assert self.columns
		assert status
		items = [self.formatItem(status.get(k, '?'), k) for k in self.columns]
		self.writeCSVLine(items)
	
	def formatItem(self, item, columnDisplayName):
		"""
		Converts numbers and other data types into strings. 
		
		Escaping is performed later. 
		
		By default, the comma grouping separator is used for large numbers, 
		as this makes them easier to read when opened in excel. 
		If people want to machine-read then the json format is probably easier 
		anyway. 
		"""
		try:
			if item is None: return '?'
			if columnDisplayName in ['seconds'] and item: 
				return f'{item:.3f}'
			if columnDisplayName == 'datetime':
				return item[:item.find('.')] # strip off seconds as excel misformats it if present
			if isinstance(item, float) and item.is_integer and abs(item)>=1000.0:
				item = int(item) # don't show decimal points for large floats like 7000.0, for consistency with smaller values like 7 when shown in excel (weird excel rules)
			if isinstance(item, int):
				return f'{item:,}'
			if isinstance(item, float):
				return f'{item:,.2f}' # deliberately make it different from the 3 we use for grouping e.g. mem usage kb->MB
			if item in [True,False]: return str(item).upper()
			return str(item)
		except Exception as ex:
			raise Exception(f'Failed to format "{columnDisplayName}" value {repr(item)}: {ex}')
	
	def writeCSVLine(self, items):
		"""
		Writes a line of CSV output, with appropriate escaping. 
		
		@param items: a list of strings, integer or floats to be written to the file. 
		Escaping will be performed
		"""
		items = ['"%s"'%(i.replace('"', '""')) if (',' in i or '"' in i) else i for i in items]
		self.output.write(','.join(items)+'\n')

class JSONStatusWriter(BaseWriter):
	output_file = 'status_@LOG_NAME@.json'

	def writeHeader(self, columns=None, extraInfo=None, **extra):
		self.output = self.createFile(self.output_file)
		# write one log line per json line, for ease of testing
		self.output.write('{"metadata":%s, "status":['%json.dumps(extraInfo or {}, ensure_ascii=False, indent=4, sort_keys=False))
		self.prependComma = False
		
	def writeStatus(self, status=None, **extra):
		assert status
		# write it out incrementally to avoid excessive memory consumption
		if self.prependComma: self.output.write(', ')
		self.output.write(u'\n'+json.dumps(status))
		self.prependComma = True

	def _writeFooter(self, **extra):
		self.output.write('\n]}\n')

################################################################################
#
# Analyzer

class LogAnalyzer(object):
	"""
	Managers analysis of one or more log files. 
	"""

	def __init__(self, args):
		self.__listeners = {} # key = eventtype, value=list of listeners
		self.args = args
		self.outputdir = args.output
		
		self.currentfile = None
		self.currentname = None # identifies the current correlator instance
		self.writers = [CSVStatusWriter(self)]
		if args.statusjson:
			self.writers.append(JSONStatusWriter(self))
	
	def processFiles(self, files):
		for name, path in files:
			if not os.path.isfile(path): raise UserError(f'Cannot find file "{path}"')
		for name, path in files:
			self.processFile(path)
		self.handleAllFilesFinished()

	def processFile(self, file):
		duration = time.time()
		# open in utf-8 with repl chars
		
		self.currentfile, self.currentname, self.currentfilebytes = file, self.logFileToLogName(file), os.path.getsize(file)
		
		log.info('Starting analysis of %s (%s MB)', os.path.basename(file), '{:,}'.format(int(self.currentfilebytes/1024.0/1024)))
		self.handleFileStarted(file=file)
		self.handleFilePercentComplete(percent=0)

		lastpercent = 0
		
		with io.open(file, encoding='utf-8', errors='replace') as f:
			self.__currentfilehandle = f
			charcount = 0
			lineno = 0
			for line in f:
				lineno += 1
				charcount += len(line)
				
				if self.currentfilebytes < 10*1000 or lineno % 10 == 0: # don't do it too often for large files
					# can't use tell() on a text file (without inefficiency), so assume 1 byte per char (usually true for ascii) as a rough heuristic
					percent = 100.0*charcount / (self.currentfilebytes or -1) # (-1 is to avoid div by zero when we're testing against a fake)
					for threshold in [25, 50, 75]:
						if percent >= threshold and lastpercent < threshold:
							self.handleFilePercentComplete(percent=threshold)
							lastpercent = threshold
				
				self.currentlineno = lineno
				line = line.rstrip()
				
				if len(line)==0: continue # blank lines aren't useful
				
				try:
					logline = LogLine(line, lineno)
					self.handleLine(line=logline)

				except Exception as e:
					log.exception(u'Failed to handle %s:%s %s - '%(line, os.path.basename(self.currentfile), self.currentlineno))
					raise

		# publish 100% and any earlier ones that were skipped if it's a tiny file
		for threshold in [25, 50, 75, 100]:
			if lastpercent < threshold:
				self.handleFilePercentComplete(percent=threshold)
		self.handleFileFinished()
		
		self.currentlineno = -1
		self.__currentfilehandle = None
		self.currentfile, self.currentfilebytes = None, 0

		duration = time.time()-duration
		if duration > 10:
			log.info('Completed analysis of %s in %s', os.path.basename(file), (('%d seconds'%duration) if duration < 120 else ('%0.1f minutes' % (duration/60))))

	def handleFileFinished(self):
		for w in self.writers:
			w.closeFile()
		self.writeStatusSummaryForCurrentFile()

	def handleAllFilesFinished(self):
		pass

	def handleFileStarted(self, file):
		# for handleRawStatusDict
		self.columns = None # ordered dict of key:annotated_displayname
		self.previousRawStatus = None # the previous raw status
		self.errorCount = self.warnCount = 0
		
		# for handleAnnotatedStatusDict summarization
		self.status_min = self.status_max = self.status_sum = \
			self.status_0pc = self.status_25pc = self.status_50pc = self.status_75pc = self.status_100pc = None
		self.previousAnnotatedStatus = None # annotated status
		self.totalStatusLinesInFile = 0

	def handleLine(self, line, **extra):
		m = line.message
		if m.startswith('Correlator Status: ') or m.startswith('Status: sm'): # "Status: " is for very old versions e.g. 4.3
			self.handleRawStatusLine(line=line)
			return
			
		level = line.level
		if level == 'W':
			self.handleWarnOrError(isError=False, line=line)
		elif level == 'E' or level == 'F':
			self.handleWarnOrError(isError=True, line=line)
		
	def handleRawStatusLine(self, line, **extra):
		m = line.message
		d = collections.OrderedDict()
		d['datetime'] = line.getDetails()['datetimestring']
		d['seconds'] = line.getDateTime().timestamp()
		d['line num'] = line.lineno
		
		"""if kind==EVENT_JMS_STATUS_DICT:
		
			if m.endswith('<waiting for onApplicationInitialized>'):
				d['waitingForOnAppInit'] = True
				m = m[:m.index('<waiting for onApplicationInitialized')-1]
			else:
				d['waitingForOnAppInit'] = False
		"""
		i = m.index(':')+2
		while i < len(m):
			# cope with space-delimited values and/or strings
			key = ''
			while i < len(m) and m[i]!='=':
				key+= m[i]
				i += 1
			assert i < len(m), repr(m)
			assert m[i] == '=', (m, repr(m[i]))
			i+=1
			if m[i]=='"':
				endchar = '"'
				i+=1
			else:
				endchar = ' '
			val = ''
			while i < len(m) and m[i] != endchar:
				if endchar != '"' or m[i] != ',': # if not a string, suppress thousands character
					val += m[i]
				i+=1
			#if kind == EVENT_JMS_STATUS_DICT: key = 'jms.'+key
			if endchar != '"':
				try:
					if '.' in val:
						val = float(val)
					else:
						val = int(val)
				except Exception:
					pass
			d[key] = val
			while i < len(m) and m[i] in [' ', '"']: i+=1
		if not d: return
		
		#log.debug('Extracted status line %s: %s', d)
		self.handleRawStatusDict(status=d)
		
		"""
		also requires this in file started:
		# for handleRawStatusLine
		self.__jmsenabled = None
		self.__previous = None # rawstatusdict

		
		if self.__jmsenabled is None:
			if self.__previous is None:
				 # don't know yet if JMS is enabled
				 self.__previous = d
				 return
			if kind is EVENT_CORRELATOR_STATUS_DICT:
				self.__jmsenabled = False # two consecutive non-JMS statuses means its not enabled
				self.handleRawStatusDict(status=self.__previous, line=line)
				self.__previous = None
			else:
				self.__jmsenabled = True
		
		if self.__jmsenabled is False:
			self.manager.publish(EVENT_COMBINED_STATUS_DICT, status=d, line=line)
		else:
			if kind is EVENT_JMS_STATUS_DICT:
				combined = collections.OrderedDict(d)
				combined.update(self.__previous)
				self.handleRawStatusDict(status=combined, line=line)
				self.__previous = None
			else:
				assert self.__previous is None, self.__previous
				self.__previous = d # will publish it once we get the JMS line immediately following
		# nb: this algorithm means a file containing only one correlator status line would be ignored, but don't care about that case really
		"""
	
		
	def handleRawStatusDict(self, status=None, **extra):
		"""
		Accepts a raw status dictionary and converts it to an annotated status 
		dict (unordered) whose keys match the columns returned by 
		decideColumns, adding in calculated values. 
		
		"""
		# the previous annotated status, if available, or None if not. 
		previousStatus = self.previousRawStatus

		if self.columns is None: # first time around
			def decideColumns(status):
				"""
				Returns a dict mapping key= to the display name column headings that will be used 
				for every line in the file, based on a prototype status dictionary. 
				"""
				columns = {}
				allkeys = set(status.keys())
				for k in COLUMN_DISPLAY_NAMES:
					if k.startswith('='):
						columns[k] = k[1:]
					elif k in allkeys:
						columns[k] = COLUMN_DISPLAY_NAMES[k]
						allkeys.remove(k)
					else:
						log.debug('This log file does not contain key: %s', k)
				for k in status:
					if k in allkeys:
						columns[k] = k
				
				return columns

			self.columns = decideColumns(status)
			for w in self.writers:
				w.writeHeader(
					columns=self.columns.values(), 
					extraInfo=self.getMetadataDictForCurrentFile()
				)
			
		d = {}
		display = self.columns # local var to speed up lookup
		
		seconds = status['seconds'] # floating point epoch seconds
		
		secsSinceLast = -1 if previousStatus is None else seconds-previousStatus['seconds']

		# treat warns/errors before the first status line as if they were after, else they won't be seen in the rate
		status['warns'] = 0 if previousStatus is None else self.warnCount
		status['errors'] = 0 if previousStatus is None else self.errorCount
		
		for k in display:
			if k.startswith('='): # computed values
				if k == '=is swapping':
					try:
						val = 1 if (status['si']+status['so']>0) else 0
					except KeyError: # not present in all Apama versions
						continue

				elif previousStatus is None or secsSinceLast==0: # can't calculate rates until we have a baseline
					val = 0

				elif k == '=errors /sec':
					val = (self.errorCount-previousStatus['errors'])/secsSinceLast
				elif k == '=warns /sec':
					val = (self.warnCount-previousStatus['warns']) /secsSinceLast
				elif k == '=log lines /sec':
					val = (status['line num']-previousStatus['line num'])/secsSinceLast

				elif k == '=rx /sec':
					val = (status['rx']-previousStatus['rx'])/secsSinceLast
				elif k == '=tx /sec':
					val = (status['tx']-previousStatus['tx'])/secsSinceLast
				elif k == '=rt /sec':
					val = (status['rt']-previousStatus['rt'])/secsSinceLast
				elif k == '=pm delta MB':
					try:
						val = (status['pm']-previousStatus['pm'])/1024.0
					except KeyError: # not present in all Apama versions
						continue
				elif k == '=vm delta MB':
					val = (status['vm']-previousStatus['vm'])/1024.0
				elif k == '=jvm delta MB':
					try:
						val = (status['jvm']-previousStatus['jvm'])/1024.0
					except KeyError: # not present in all Apama versions
						continue
				else:
					assert False, 'Unknown generated key: %s'%k
			else:
				val = status.get(k, None)
				if display[k] in ['pm=resident MB', 'vm=virtual MB', 'jvm=Java MB'] and val is not None:
					val = val/1024.0 # kb to MB
			d[display[k]] = val

		self.handleAnnotatedStatusDict(status=d)
		self.previousRawStatus = status # both raw and annotated values

	def handleAnnotatedStatusDict(self, status, **extra):
		for w in self.writers:
			w.writeStatus(status=status)
		self._updateStatusSummary(status=status)

	############################################################################
	# summarization

	def _updateStatusSummary(self, status):
		"""
		Called for each parsed and annotated status value to allow us to update per-file summary stats
		"""
	
		# summary
		if self.previousAnnotatedStatus is None: 
			self.status_0pc = dict(status)
			self.status_sum = {k:0 for k in status} 
			self.status_min = dict(status)
			self.status_max = dict(status)
		self.previousAnnotatedStatus = status
		self.totalStatusLinesInFile += 1
		for k, v in status.items():
			if isinstance(v, str): continue
			if v > self.status_max[k]: self.status_max[k] = v
			if v < self.status_min[k]: self.status_min[k] = v
			
			if v != 0: 
				if isinstance(self.status_0pc[k], float): 
					# for precision, use integers (which in python have infinite precision!) 
					# to keep runnning total, even for float types; 
					# to get final number that look right to 4 dp, scale up by 6 dp
					v = int(1000000*v) 
				self.status_sum[k] += v

	def handleFilePercentComplete(self, percent, **extra):
		# update status summary
		if percent >= 25:
			self.status_25pc = self.status_25pc or self.previousAnnotatedStatus
		if percent >= 50:
			self.status_50pc = self.status_50pc or self.previousAnnotatedStatus
		if percent >= 75:
			self.status_75pc = self.status_75pc or self.previousAnnotatedStatus
		if percent == 100:
			self.status_100pc = self.previousAnnotatedStatus

	def writeStatusSummaryForCurrentFile(self):
		""" Called when the current log file is finished to write out status summary csv/json. 
		"""
		if self.totalStatusLinesInFile < 2 or (not self.previousAnnotatedStatus) or (not self.status_100pc):
			log.warn('%d status line(s) found in %s; not enough to analyze', self.totalStatusLinesInFile, self.currentname)
			return

		def numberOrEmpty(v):
			if v is None or isinstance(v, str):
				return ''
			return v
		
		def calcmean(k):
			v = self.status_sum[k]
			if v is None or isinstance(v, str) or isinstance(self.status_0pc.get(k, ''), str): return ''

			# to get improved precision we convert floats to ints, scaling up  - turn them back here
			if isinstance(self.status_0pc[k], float): v = v/1000000.0

			v = v / float(self.totalStatusLinesInFile) # force a floating point division
			if v==0: v = 0 # keep it concise for zero values
			
			
			# don't bother with decimal places for large integer values
			if abs(v) > 1000 and isinstance(self.status_0pc.get(k, ''), int): v = int(v)
			
			return v
			
		rows = {
			'0% (start)':self.status_0pc,
			'25%':self.status_25pc,
			'50%':self.status_50pc,
			'75%':self.status_75pc,
			'100% (end)':self.status_100pc,
			'':None,
			'min':{k: numberOrEmpty(self.status_min[k]) for k in self.status_min},
			'mean':{k: calcmean(k) for k in self.status_sum},
			'max':{k: numberOrEmpty(self.status_max[k]) for k in self.status_max},
		}
		for k in self.status_0pc:
			if isinstance(self.status_0pc[k], str):
				self.status_sum[k] = ''
				self.status_min[k] = ''
				self.status_max[k] = ''

		writers = [CSVStatusWriter(self), JSONStatusWriter(self)]
		for w in writers:
			w.output_file = 'summary_'+w.output_file.split('_', 1)[1]
			w.writeHeader(columns = ['statistic']+list(self.columns.values()), extraInfo=self.getMetadataDictForCurrentFile())
			prev = None
			for display, status in rows.items():
				if not display:
					prev = None
					w.output.write('\n') # add a blank line to provide visual separation
					continue
				
				if prev:
					# show deltas between the lines is quite handy
					delta = collections.OrderedDict()
					delta['statistic'] = f'... delta: {display} - {prev["statistic"]}'
					for k in status:
						if isinstance(status[k], str) or k in ['seconds', 'line num']:
							delta[k] = ''
						else:
							try:
								delta[k] = status[k]-prev[k]
							except Exception as ex:
								delta[k] = f'delta exception: {ex}'
					w.writeStatus(delta)
					
				status = collections.OrderedDict(status)
				status['statistic'] = display
				if '%' not in display:
					status['datetime'] = status['seconds'] = ''
					if 'mean' in display:
						status['seconds'] = ''
				status.move_to_end('statistic', last=False)
				w.writeStatus(status)
				prev = status
			w.closeFile()

	def handleWarnOrError(self, isError, line, **extra):
		if isError:
			self.errorCount += 1
		else:
			self.warnCount += 1

	def getMetadataDictForCurrentFile(self):
		""" Get an ordered dictionary of additional information to be included with the header for the current file, 
		such as date, version, etc. """
		d = collections.OrderedDict()
		d['analyzer'] = f'v{__version__}/{__date__}' # always include the version of the script that generated it
		return d


	@staticmethod
	def logFileToLogName(filename):
		"""Converts a .log filename to a base name to identify the associated 
		correlator instance, which can be used as the basis for output filenames. 
		"""
		assert filename
		return os.path.basename(filename).replace('.output.log','').replace('.log','')


class LogAnalyzerTool(object):
	"""
	Class for the command line tool. Subclass this if you wish to add extra 
	arguments to the parser. 
	
	@ivar argparser: A argparse.ArgumentParser that subclasses can add arguments to if desired. 
	"""
	def __init__(self):
		self.argparser = argparse.ArgumentParser(description=u'Analyzes Apama correlator log files v%s/%s'%(__version__, __date__), 
			epilog=u'For Apama versions before 10.3 only the first log file contains the header section specifying version and environment information, so be sure to include that first log file otherwise critical information will be missing.')
			
		self.argparser.add_argument('--loglevel', '-l', '-v', default='INFO',
			help='Log level/verbosity for this tool')
		self.argparser.add_argument('files', metavar='FILE', nargs='+',
			help='One or more correlator log files to be analyzed; glob-style expressions e.g. *.log are permitted')
		self.argparser.add_argument('--output', '-o', metavar='DIR',  # later might also support zip output
			help='The directory to which output files will be written. Existing files are overwritten if it already exists.')

		self.argparser.add_argument('--statusjson', action='store_true',
			help='Advanced/debugging option to extract status lines in json format suitable for processing by scripts.')
		
	def main(self, args):
		args = self.argparser.parse_args(args)

		loglevel = getattr(logging, args.loglevel.upper())
		logging.basicConfig(format=u'%(relativeCreated)05d %(levelname)-5s - %(message)s' if loglevel == logging.DEBUG 
			else u'%(levelname)-5s - %(message)s', 
			stream=sys.stderr, level=loglevel)

		log.info('Apama correlator log analyzer v%s/%s'%(__version__, __date__))
		
		duration = time.time()
		
		logfiles = []
		def addlog(f):
			name = LogAnalyzer.logFileToLogName(f)
			if not os.path.isfile(f):
				raise UserError(f'Cannot find log file: {os.path.normpath(f)}')
			logfiles.append( (name, f))
			
		for f in args.files: # probably want to factor this out to an overridable method
			if '*' in f:
				globbed = sorted(glob.glob(f))
				if not globbed:
					raise UserError(f'No files found matching glob: {f}')
				for f in globbed: addlog(f)
			else:
				addlog(f)
				
			# TODO: add directory analysis, incl special-casing of "logs/" and ignoring already-analyzed files. zip file handling. 
			
		logfiles.sort() # hopefully puts the latest one at the end
		
		if not logfiles: raise UserError('No log files specified')
		
		if not args.output: 
			# if not explicitly specified, create a new unique dir
			outputname = 'log_analyzer_%s'%logfiles[-1][0] # base it on the most recent name
			args.output = outputname
			i = 2
			while os.path.exists(args.output) and os.listdir(args.output): # unless it's empty
				args.output = '%s_%02d'%(outputname, i)
				i += 1

		log.info('Output directory is: %s', os.path.abspath(args.output))
		assert os.path.abspath(args.output) != os.path.abspath(os.path.dirname(logfiles[-1][0])), 'Please put output into a different directory to the input log files'
		if not os.path.exists(args.output): os.makedirs(args.output)
		
		manager = self.createManager(args)
		manager.processFiles(logfiles)

		duration = time.time()-duration
		log.info('Completed analysis in %s', (('%d seconds'%duration) if duration < 120 else ('%0.1f minutes' % (duration/60))))

		log.info('')
		log.info('If you need to request help analyzing a log file be sure to tell us: the 4-digit Apama version, the time period when the bad behaviour was observed, any ERROR/WARN messages, who is the author/expert of the EPL application code, and if possible attach the full original correlator log files (including the very first log file - which contains all the header information - and the log file during which the bad behaviour occurred). ')
		
		return 0
	
	def createManager(self, args):
		return LogAnalyzer(args)
	
if __name__ == "__main__":
	try:
		sys.exit(LogAnalyzerTool().main(sys.argv[1:]))
	except UserError as ex:
		sys.stderr.write(f'ERROR - {ex}\n')
		sys.exit(100)
