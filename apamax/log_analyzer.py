#!/usr/bin/env python3

""" This is a Python 3 script for analyzing Apama correlator (and apama-ctrl) log files. 

It extracts and summarizes information from status lines and other log messages.


Copyright (c) 2019 Software AG, Darmstadt, Germany and/or its licensors

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. 
See the License for the specific language governing permissions and limitations under the License.

These tools are provided as-is and without warranty or support. They do not constitute part of the Software AG product suite. Users are free to use, fork and modify them, subject to the license agreement. 

"""

__version__ = '3.1.dev'
__date__ = '2019-10-18'
__author__ = "Apama community"
__license__ = "Apache 2.0"

import logging, os, io, argparse, re, time, sys, collections, datetime, calendar
import json
import glob
import math
import shutil
from typing import List, Dict # Python 3 type hints

log = logging.getLogger('loganalyzer')
log.warn = None # make it an error, since Python 3.7 isn't happy unless you use .warning

COLUMN_DISPLAY_NAMES = collections.OrderedDict([
	# timing
	('datetime', 'local datetime'), # date time string
	('epoch secs', None), # secs since the 1970 epoch; currently this in local time (which isn't ideal)
	('=interval secs', None), # interval time between , in case people want to calculate rates.
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
	('jvm','jvm=Java MB'), # this is the "total used" memory (also available in JMS line)
	
	('=pm delta MB', None),
	('=vm delta MB', None),
	('=jvm delta MB', None),

	# swapping
	('si','si=swap pages read /sec'),
	('so','so=swap pages written /sec'),
	('=is swapping', None), # 1 if swapping, 0 if not; use integer not bool so we can graph it and sum it
	
	# log messages
	('=errors',None), # since last status
	('=warns',None),
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
	
	@ivar extraLines: unassigned, or a list of strings which are extra lines logically part of this one (typically for warn/error stacks etc)
	"""
	#                          date                                        level     thread       apama-ctrl/std cat  message
	LINE_REGEX = re.compile(r'(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d[.]\d\d\d) ([A-Z#]+) +\[([^\]]+)\] ([^-]*)-( <[^>]+>)? (.*)')
	
	__slots__ = ['line', 'lineno', 'message', 'level', '__details', 'extraLines'] # be memory-efficient
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
			if isapamactrl:
				 # use '] ' for apama-ctrl so we can capture the log category
				self.message = f'<apama-ctrl> {line[line.find("] ")+2:]}'
			else:
				self.message = line[i+3:]
			
			try:
				self.level = line[24] # this is a nice efficient way to get the log level without slow regexes
			except IndexError: # just in case it's not a normal log line (though we hope the firstchar.isdigit() check will catch most of those)
				self.level = None
		else:
			self.message = line
			self.level = None
	
	def getDetails(self):
		"""
		Returns a dictionary containing: datetimestring, thread
		
		The result is cached, as getting this data is a bit time-consuming; avoid calling this unless you're sure you need it. 
		"""
	
		det = self.__details
		if det is not None: return det
		if self.level is not None: # signifies it's not a proper log line
			m = LogLine.LINE_REGEX.match(self.line)
			if m:
				g = m.groups()
				self.__details = {
					'datetimestring':g[0],
					'thread':g[2],
					#'logcategory': (g[3] or g[4] or '').strip(),
					#'messagewithoutcat':g[5],
				}
				return self.__details
			else:
				log.debug('Log line starts with a digit but does not match regex: %s', self.line)

		self.__details = {
					'datetimestring':'',
					'thread':'',
					#'logcategory':'',
					#'messagewithoutcat':self.message,
				}
		self.level = None # to indicate it's not a proper valid log line after all
		return self.__details
	
	def getDateTime(self):
		"""
		Parse the datetime object from this log line. Don't do this unless you need it.  
		
		Returns None if this isn't a properly formatted log line with a date and time etc
		"""
		if self.level is None: return None
		det = self.getDetails()
		if 'datetime' in det: # cache this
			return det['datetime']
			
		try:
			d = datetime.datetime.strptime(self.getDetails()['datetimestring'], '%Y-%m-%d %H:%M:%S.%f')
		except Exception as ex: # might not be a valid line
			log.debug('Cannot parse date time from "%s": %s - from line: %s', self.getDetails()['datetimestring'], ex, self.line)
			return None
		det['datetime'] = d
		return d

	def getDateTimeString(self):
		return LogAnalyzer.formatDateTime(self.getDateTime())
	
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
	output_file = 'status.@LOG_NAME@.csv'

	def writeHeader(self, columns=None, extraInfo=None, **extra):
		self.output = self.createFile(self.output_file)
		
		# write this special header to tell excel to treat csv as comma separated even in locales where , normally is used as a decimal separator
		self.output.write("sep=,\n")
		
		self.columns = columns
		items = list(columns)
		items[0] = '# '+items[0]
		if extraInfo:
			items.append('# metadata: ')
			
			# this is a relatively CSV-friendly way of putting extra metadata into the file without messing with the main columns
			#items.extend(['%s=%s'%(k, extraInfo[k]) for k in extraInfo])
			for k in extraInfo: items.extend([f'{k}=', self.formatItem(extraInfo[k], k)])
		self.writeCSVLine(items)
		
	def writeStatus(self, status=None, missingItemValue='?', **extra):
		#assert self.columns
		#assert status
		items = [self.formatItem(status.get(k), k, missingItemValue=missingItemValue) for k in self.columns]
		self.writeCSVLine(items)
	
	def formatItem(self, item, columnDisplayName, missingItemValue='?'):
		"""
		Converts numbers and other data types into strings. 
		
		Escaping is performed later. 
		
		By default, the comma grouping separator is used for large numbers, 
		as this makes them easier to read when opened in excel. 
		If people want to machine-read then the json format is probably easier 
		anyway. 
		"""
		try:
			if item is None: return missingItemValue
			if columnDisplayName == 'local datetime':
				return item[:item.find('.')] # strip off seconds as excel misformats it if present
			if isinstance(item, float) and item.is_integer and abs(item)>=1000.0:
				item = int(item) # don't show decimal points for large floats like 7000.0, for consistency with smaller values like 7 when shown in excel (weird excel rules)
			if isinstance(item, int):
				if columnDisplayName=='epoch secs':
					return f'{item}'
				return f'{item:,}'
			if isinstance(item, float):
				return f'{item:,.2f}' # deliberately make it different from the 3 we use for grouping e.g. mem usage kb->MB
			if isinstance(item, list): # e.g. for notableFeatures list
				return '; '.join(item)
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
	output_file = 'status.@LOG_NAME@.json'

	@staticmethod
	def encodeCustomObjectAsJSON(o):
		if isinstance(o, LogLine):
			return {'lineno':o.lineno, 'datetime':o.getDateTime()}
		if isinstance(o, datetime.datetime):
			return o.strftime('%Y-%m-%d %H:%M:%S')
		raise TypeError('Unhandled JSON type: %r'%o)

	@staticmethod
	def toMultilineJSON(data):
		return json.dumps(data, ensure_ascii=False, indent=4, sort_keys=False, default=JSONStatusWriter.encodeCustomObjectAsJSON)

	def writeHeader(self, columns=None, extraInfo=None, **extra):
		self.output = self.createFile(self.output_file)
		# write one log line per json line, for ease of testing
		self.output.write('{"metadata":%s, "status":['%JSONStatusWriter.toMultilineJSON(extraInfo or {}))
		self.prependComma = False
		
	def writeStatus(self, status=None, **extra):
		#assert status
		# write it out incrementally to avoid excessive memory consumption
		if self.prependComma: self.output.write(', ')
		self.output.write(u'\n'+json.dumps(status, default=JSONStatusWriter.encodeCustomObjectAsJSON))
		self.prependComma = True

	def _writeFooter(self, **extra):
		self.output.write('\n]}\n')

################################################################################
#
# Analyzer

class LogAnalyzer(object):
	"""
	Managers analysis of one or more log files. 
	
	@ivar currentname: The display name of the log file currently being processed
	@ivar currentpath: The full path of the log file currently being processed
	@ivar current: The dictionary of the current log file. 
	"""

	def __init__(self, args):
		self.__listeners = {} # key = eventtype, value=list of listeners
		self.args = args
		self.outputdir = args.output
		
		self.writers = [CSVStatusWriter(self)]
		if args.json:
			self.writers.append(JSONStatusWriter(self))
	
	def processFiles(self, filepaths):
		for path in filepaths:
			if not os.path.isfile(path): raise UserError(f'Cannot find file "{path}"')
		self.files = [ # list of dictionaries
			{'path':fp, 'name': self.logFileToLogName(fp), 'startTime':None, 'endTime':None}
			for fp in filepaths
		]
		self.handleAllFilesStarted()
		for file in self.files:
			self.processFile(file=file)
		self.handleAllFilesFinished()
		self.files = None

	def processFile(self, file):
		"""
		@param file: The dictionary for the file to be processed. 
		"""
		duration = time.time()
		
		self.currentpath = file['path']
		self.currentname = file['name']
		self.currentpathbytes = os.path.getsize(self.currentpath)
		
		log.info('Starting analysis of %s (%s MB)', os.path.basename(self.currentpath), '{:,}'.format(int(self.currentpathbytes/1024.0/1024)))
		self.handleFileStarted(file=file)
		self.handleFilePercentComplete(file=file, percent=0)

		lastpercent = 0
		
		finalLineWithTimestamp = None
		
		with io.open(self.currentpath, encoding='utf-8', errors='replace') as f:
			self.__currentfilehandle = f
			charcount = 0
			lineno = 0
			previousLine = None
			startTime = None
			for line in f:
				lineno += 1
				charcount += len(line)
				
				if self.currentpathbytes < 10*1000 or lineno % 10 == 0: # don't do it too often for large files
					# can't use tell() on a text file (without inefficiency), so assume 1 byte per char (usually true for ascii) as a rough heuristic
					percent = 100.0*charcount / (self.currentpathbytes or -1) # (-1 is to avoid div by zero when we're testing against a fake)
					for threshold in [25, 50, 75]:
						if percent >= threshold and lastpercent < threshold:
							self.handleFilePercentComplete(file=file, percent=threshold)
							lastpercent = threshold
				
				self.currentlineno = lineno
				
				line = line.rstrip()
				
				if len(line)==0: continue # blank lines aren't useful
				
				try:
					logline = LogLine(line, lineno)
					if startTime is None and logline.level is not None: 
						startTime = logline.getDateTime()
						file['startTime'] = startTime
					
					if self.handleLine(file=file, line=logline, previousLine=previousLine) != LogAnalyzer.DONT_UPDATE_PREVIOUS_LINE:
						previousLine = logline
					if logline.level is not None: finalLineWithTimestamp = logline

				except Exception as e:
					log.exception(f'Failed to handle {os.path.basename(self.currentpath)} line {self.currentlineno}: {line} - ')
					raise
			if finalLineWithTimestamp is not None:
				file['endTime'] = finalLineWithTimestamp.getDateTime()

		# publish 100% and any earlier ones that were skipped if it's a tiny file
		for threshold in [25, 50, 75, 100]:
			if lastpercent < threshold:
				self.handleFilePercentComplete(file=file, percent=threshold)
		self.handleFileFinished(file=file)

		duration = time.time()-duration
		if duration > 10:
			log.info('Completed analysis of %s in %s', os.path.basename(self.currentpath), (('%d seconds'%duration) if duration < 120 else ('%0.1f minutes' % (duration/60))))
		
		self.currentlineno = -1
		self.__currentfilehandle = None
		self.currentpath, self.currentpathbytes = None, 0
		self.currentfile = file

	def handleFileFinished(self, file, **extra):
		for w in self.writers:
			w.closeFile()
		self.writeStatusSummaryForCurrentFile(file=file)
		
		self.writeStartupStanzaSummaryForCurrentFile(file=file)
		self.writeConnectionMessagesForCurrentFile(file=file)

	def handleAllFilesFinished(self):
		self.writeWarnOrErrorSummaryForAllFiles()
		self.writeOverviewForAllFiles()

	def handleAllFilesStarted(self):
		# for handleWarnOrError
		self.warns = {} # {normmsg: {logfile:{first:logline, last:logline, all:[logline]}}}
		self.errors = {}

	def handleFileStarted(self, file, **extra):
		# for handleRawStatusDict
		self.columns = None # ordered dict of key:annotated_displayname
		self.previousRawStatus = None # the previous raw status
		file['errorsCount'] = file['warningsCount'] = 0
		
		# for handleAnnotatedStatusDict summarization
		file['status-min'] = file['status-max'] = file['status-sum'] = \
			file['status-0pc'] = file['status-25pc'] = file['status-50pc'] = file['status-75pc'] = file['status-100pc'] = None
		self.previousAnnotatedStatus = None # annotated status
		self.totalStatusLinesInFile = 0
		
		file['startupStanzas'] = [{}]
		file['inStartupStanza'] = False
		
		file['connectionMessages'] : List = []
		file['connectionIds'] : Dict[str,int] = {}
		

	DONT_UPDATE_PREVIOUS_LINE = 123
	def handleLine(self, file, line, previousLine, **extra):
		m = line.message
		if m.startswith(('Correlator Status: ', 'Status: sm')): # "Status: " is for very old versions e.g. 4.3
			self.handleRawStatusLine(file=file, line=line)
			return
			
		level = line.level
		if level == 'W':
			self.handleWarnOrError(file=file, isError=False, line=line)
		elif level in {'E', 'F'}:
			# handle multi-line errors. Usually we need time AND thread to match, but FATAL stack trace lines are logged independently
			if previousLine is not None and previousLine.level == level and previousLine.getDetails()['thread']==line.getDetails()['thread'] and (
					level=='F' or previousLine.getDateTime()==line.getDateTime()):
				# treat a line with no date/level this as part of the preceding warn/error message
				if not hasattr(previousLine, 'extraLines'): previousLine.extraLines = []
				previousLine.extraLines.append(line.line)
				return LogAnalyzer.DONT_UPDATE_PREVIOUS_LINE
		
			self.handleWarnOrError(file=file, isError=True, line=line)
		elif level is None:
			if previousLine is not None and previousLine.level in {'W', 'E', 'F'}:
				# treat a line with no date/level this as part of the preceding warn/error message
				if not hasattr(previousLine, 'extraLines'): previousLine.extraLines = []
				previousLine.extraLines.append(line.line)
			elif m.startswith('Running correlator [') and ' ##### ' in m:
				# workaround for annoying bug in apama-ctrl's runDeploy.py in 10.3.2 to 10.5.0.0 (inclusive) which contains the first correlator startup line
				return self.handleLine(file=file, line=LogLine(m[m.find(' #####' )-23:], lineno=line.lineno), previousLine=previousLine, **extra)
			
			return LogAnalyzer.DONT_UPDATE_PREVIOUS_LINE # previous line must always be a valid line with a level etc (ignore initial spring boot lines in apama-ctrl log)
		elif level == '#' or (file['inStartupStanza'] and level == 'I') or previousLine is None:
			# also grab info lines within a startup stanza, and (for the benefit of apama-ctrl) the very first line of the file regardless
			self.handleStartupLine(file=file, line=line)
		elif level == 'I' and m.startswith((
			'The receiver ',
			'Receiver ',
			'Blocking receiver ',
			)):
				self.handleConnectionMessage(file, line)
	
	def handleRawStatusLine(self, file, line, **extra):
		m = line.message
		d = collections.OrderedDict()
		d['datetime'] = line.getDetails()['datetimestring']
		
		# TODO: fix the epoch calculation; treating this as UTC isn't correct since it probably isn't
		d['epoch secs'] = line.getDateTime().replace(tzinfo=datetime.timezone.utc).timestamp()

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
		self.handleRawStatusDict(file=file, line=line, status=d)
		
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
	
		
	def handleRawStatusDict(self, file, line, status=None, **extra):
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
				columns = collections.OrderedDict()
				allkeys = set(status.keys())
				for k in COLUMN_DISPLAY_NAMES:
					if k.startswith('='):
						columns[k] = k[1:]
					elif k in allkeys:
						columns[k] = COLUMN_DISPLAY_NAMES[k] or k
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
					extraInfo=self.getMetadataDictForCurrentFile(file=file)
				)
			
		d = {}
		display = self.columns # local var to speed up lookup
		
		seconds = status['epoch secs'] # floating point epoch seconds
		
		if previousStatus is None:
			if file['startTime'] is not None:
				secsSinceLast = status['epoch secs']-file['startTime'].replace(tzinfo=datetime.timezone.utc).timestamp()
			else:
				secsSinceLast = -1 # hopefully won't happen
		else:
			secsSinceLast = seconds-previousStatus['epoch secs']

		# treat warns/errors before the first status line as if they were after, else they won't be seen in the first value
		status['warns'] = 0 if previousStatus is None else file['warningsCount']
		status['errors'] = 0 if previousStatus is None else file['errorsCount']
		for k in display:
			if k.startswith('='): # computed values
				if k == '=is swapping':
					try:
						val = 1 if (status['si']+status['so']>0) else 0
					except KeyError: # not present in all Apama versions
						continue
					if val == 1: 
						file.setdefault('swappingStartLine', line)
						file.pop('swappingEndLine',None)
					elif 'swappingEndLine' not in file:
						file['swappingEndLine'] = line

				elif k == '=interval secs':
					val = secsSinceLast
					
				elif previousStatus is None or secsSinceLast <= 0: # can't calculate rates if for some reason we have a negative divisor (else div by zero)
					val = 0

				elif k == '=errors':
					val = (file['errorsCount']-previousStatus['errors'])
				elif k == '=warns':
					val = (file['warningsCount']-previousStatus['warns'])

				elif k == '=log lines /sec':
					# avoid skewing the stats with data from before the start
					val = 0 if previousStatus is None else (status['line num']-previousStatus['line num'])/secsSinceLast

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
				if display[k] in ['pm=resident MB', 'vm=virtual MB'] and val is not None:
					val = val/1024.0 # kb to MB
			d[display[k]] = val

		self.handleAnnotatedStatusDict(file=file, line=line, status=d)
		self.previousRawStatus = status # both raw and annotated values

	def handleAnnotatedStatusDict(self, file, line, status, **extra):
		"""
		@param line: There may be multiple lines associated with this status; this is typically the first one
		"""
		for w in self.writers:
			w.writeStatus(status=status)
		self._updateStatusSummary(file=file, line=line, status=status)

	############################################################################
	# summarization

	def _updateStatusSummary(self, file, line, status):
		"""
		Called for each parsed and annotated status value to allow us to update per-file summary stats
		"""
	
		# summary
		if self.previousAnnotatedStatus is None: 
			file['status-0pc'] = dict(status)
			file['status-sum'] = {k:0 for k in status} 
			file['status-min'] = dict(status)
			file['status-max'] = dict(status)
			for k, v in status.items(): file['status-max'][k+'.line'] = line
			
			file['status-floatKeys'] = set()
			for k in status:
				if isinstance(status[k], float): 
					file['status-floatKeys'].add(k)
		self.previousAnnotatedStatus = status
		self.totalStatusLinesInFile += 1
		for k, v in status.items():
			if v is None or isinstance(v, str): continue
			if v < file['status-min'][k]: file['status-min'][k] = v
			if v > file['status-max'][k]: 
				file['status-max'][k] = v
				file['status-max'][k+'.line'] = line # also useful to have datetime/linenum for the maximum ones
			
			if v != 0: 
				if k in file['status-floatKeys']: 
					# for precision, use integers (which in python have infinite precision!) 
					# to keep runnning total, even for float types; 
					# to get final number that look right to 4 dp, scale up by 6 dp
					v = int(1000000*v) 
				file['status-sum'][k] += v

	def handleFilePercentComplete(self, file, percent, **extra):
		# update status summary
		if percent >= 25:
			file['status-25pc'] = file['status-25pc'] or self.previousAnnotatedStatus
		if percent >= 50:
			file['status-50pc'] = file['status-50pc'] or self.previousAnnotatedStatus
		if percent >= 75:
			file['status-75pc'] = file['status-75pc'] or self.previousAnnotatedStatus
		if percent == 100:
			file['status-100pc'] = self.previousAnnotatedStatus

	def writeStatusSummaryForCurrentFile(self, file):
		""" Called when the current log file is finished to write out status summary csv/json. 
		"""
		if self.totalStatusLinesInFile < 2 or (not self.previousAnnotatedStatus) or (not file.get('status-100pc')):
			log.warning('%d status line(s) found in %s; not enough to analyze', self.totalStatusLinesInFile, self.currentname)
			return

		def numberOrEmpty(v):
			if v is None or isinstance(v, str):
				return ''
			return v
		
		def calcmean(k):
			v = file['status-sum'][k]
			if v is None or isinstance(v, str) or isinstance(file['status-0pc'].get(k, ''), str): return ''

			# to get improved precision we convert floats to ints, scaling up  - turn them back here
			if k in file['status-floatKeys']: v = v/1000000.0

			v = v / float(self.totalStatusLinesInFile) # force a floating point division
			if v==0: v = 0 # keep it concise for zero values
			
			
			# don't bother with decimal places for large integer values
			if abs(v) > 1000 and isinstance(file['status-0pc'].get(k, ''), int): v = int(v)
			
			return v
		
		file['status-mean'] = {k: calcmean(k) for k in file['status-sum']}
		
		rows = {
			'0% (start)':file['status-0pc'],
			'25%':file['status-25pc'],
			'50%':file['status-50pc'],
			'75%':file['status-75pc'],
			'100% (end)':file['status-100pc'],
			'':None,
			'min':{k: numberOrEmpty(file['status-min'][k]) for k in file['status-min']},
			'mean':file['status-mean'],
			'max':{k: numberOrEmpty(file['status-max'][k]) for k in file['status-max']},
		}
		for k in file['status-0pc']:
			if isinstance(file['status-0pc'][k], str):
				file['status-sum'][k] = ''
				file['status-min'][k] = ''
				file['status-max'][k] = ''

		writers = [CSVStatusWriter(self)]
		if self.args.json:
			writers.append(JSONStatusWriter(self))
		for w in writers:
			w.output_file = 'summary_status.'+w.output_file.split('.', 1)[1]
			w.writeHeader(columns = ['statistic']+list(self.columns.values()), extraInfo=self.getMetadataDictForCurrentFile(file=file))
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
						if isinstance(status[k], str) or k in ['seconds', 'line num', 'interval secs'] or k.endswith('.line'):
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
					status['local datetime'] = status['seconds'] = ''
					if 'mean' in display:
						status['seconds'] = ''
				status.move_to_end('statistic', last=False)
				w.writeStatus(status)
				prev = status
			w.closeFile()

	####################################################################################################################
	# Warn/error handling

	WARN_ERROR_NORMALIZATION_REGEX = re.compile('[0-9][0-9.]*')
	def handleWarnOrError(self, file, isError, line, **extra):
		if isError:
			file['errorsCount'] += 1
			tracker = self.errors
		else:
			file['warningsCount'] += 1
			tracker = self.warns
		
		XmaxUniqueWarnOrErrorLines = self.args.XmaxUniqueWarnOrErrorLines
		
		msg = line.message
		# normalize so we can group them together
		normmsg = LogAnalyzer.WARN_ERROR_NORMALIZATION_REGEX.sub('___', msg)
		
		# bound the total amount of memory used for this data structure by limiting the number of unique messages 
		# (if the normalization regex is doing its job this hopefully won't be hit; if it is, we need a way to 
		# customize the regex, or add a new exclusions regex)
		if XmaxUniqueWarnOrErrorLines>0 and len(tracker)==XmaxUniqueWarnOrErrorLines and normmsg not in tracker:
			log.debug('Not adding new isError=%s message as XmaxUniqueWarnOrErrorLines was hit', isError)
			return
		
		tracker = tracker.setdefault(normmsg, {})
		tracker = tracker.setdefault(self.currentpath, {})
		if not tracker:
			tracker['first'] = tracker['last'] = line
			tracker['count'] = 1
			tracker['samples'] = []
		else:
			if tracker['first'].getDateTime() > line.getDateTime():
				tracker['first'] = line
			if tracker['last'].getDateTime() < line.getDateTime():
				tracker['last'] = line
			tracker['count'] += 1
			
		tracker['samples'].append(line)

		# avoid using too much memory for holding sample lines (per unique msg)
		maxSampleWarnOrErrorLines = self.args.XmaxSampleWarnOrErrorLines
		if maxSampleWarnOrErrorLines>0 and len(tracker['samples'])>maxSampleWarnOrErrorLines*2:
			tracker['samples'] = tracker['samples'][:maxSampleWarnOrErrorLines//2]+tracker['samples'][-maxSampleWarnOrErrorLines//2:]

	def writeWarnOrErrorSummaryForAllFiles(self):
		maxSampleWarnOrErrorLines = self.args.XmaxSampleWarnOrErrorLines if self.args.XmaxSampleWarnOrErrorLines>0 else None
		for kind, tracker in [('warnings', self.warns), ('errors', self.errors)]:
			if not tracker: 
				log.info(f'No {kind} were found in any of these log files.')
				continue
			
			path = f'{self.outputdir}/logged_{kind}.txt'
			with io.open(path, 'w', encoding='utf-8') as f:
				
				# first show a summary
				for file in self.files:
					f.write(f"{file[f'{kind}Count']} {kind} in {file['name']}\n")
				f.write("\n")

				if self.args.XmaxUniqueWarnOrErrorLines>0 and len(tracker)==self.args.XmaxUniqueWarnOrErrorLines:
					f.write(f'WARNING: Some messages are NOT included in this file due to the XmaxUniqueWarnOrErrorLines limit of {self.args.XmaxUniqueWarnOrErrorLines}\n\n')
					log.warning(f'Some messages are NOT included in the {kind} file due to the XmaxUniqueWarnOrErrorLines limit of {self.args.XmaxUniqueWarnOrErrorLines})')

				f.write(f"Summary of {kind}, sorted by normalized message, with number of occurrences of that message indicated by 'xN': \n\n")
				
				def writeSampleLine(prefix, line):
					f.write(f'{prefix}{line.line}\n')
					if hasattr(line, 'extraLines'):
						for e in line.extraLines:
							f.write(' '*len(prefix))
							f.write(f'{e}\n')
				
				firstmessage = True
				for normmsg in sorted(tracker):
					remainingSamples = maxSampleWarnOrErrorLines or 0
				
					byfiles = tracker[normmsg]
					totalcount = sum(byfile['count'] for byfile in byfiles.values())

					prefix = f"--- {totalcount}x: "
					firstmessage = False
					
					if totalcount == 1:
						[(logfile, byfile)] = byfiles.items()
						sampleline = byfile['samples'][0]
						
						writeSampleLine(prefix, sampleline)
						f.write(f"      in {self.logFileToLogName(logfile)} line {sampleline.lineno}\n")
						remainingSamples -= 1
					else:
						f.write(prefix)
						f.write(f"{normmsg}\n")
						for logfile, byfile in byfiles.items():
							if byfile['count'] == 1:
								f.write(f"      1x at   {self.formatDateTime(byfile['first'].getDateTime())} in {self.logFileToLogName(logfile)}\n")
							else:
								f.write(f"      {byfile['count']}x {self.formatDateTimeRange(byfile['first'].getDateTime(), byfile['last'].getDateTime())} in {self.logFileToLogName(logfile)}\n")

						for logfile, byfile in byfiles.items():
							f.write(f"      Examples from {self.logFileToLogName(logfile)}:\n")							
							
							if maxSampleWarnOrErrorLines and len(byfile['samples']) > remainingSamples:
								# first half and last half is most informative
								byfile['samples'] = byfile['samples'][:remainingSamples//2]+byfile['samples'][-remainingSamples//2:]
							
							for sampleline in byfile['samples']:
								writeSampleLine(f"       line {sampleline.lineno} : ", sampleline)
								remainingSamples -= 1
								if maxSampleWarnOrErrorLines and remainingSamples <= 0:
									break # only print the first example per file if we've already exceeded our quota

					f.write('\n')

	####################################################################################################################
	# Sender/receiver connection events

	CONNECTION_MESSAGE_IDS_REGEX = re.compile('^[(]component ID (?P<remotePhysicalId>[0-9]+)/(?P<remoteLogicalId>[0-9]+)[)] (?P<message>.+)$')
	CONNECTION_MESSAGE_ADDR_REGEX = re.compile('^(?P<message>.+) from (?P<host>[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+):(?P<remotePort>[0-9]+) *$')

	CONNECTION_LINE_REGEX = re.compile(
		# This regex is for sender/receiver connection lines;
		# the (?P<name>xxxx) syntax identifies named groups in the regular expression
	
		# TODO: could add senders here, though less useful since it's slow receivers that cause the issues usually
		# hack: hope/assume that pointer addresses are always prefixed with 00 on linux 
		"^(?P<prefix>Receiver|Connected to receiver|Blocking receiver) (?P<remoteProcessName>.+) [(](?P<object>(0x|00)[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)[)] (?P<message>.+)"
		)
		
		# TODO: check performance of this
		
		#TODO: remove "," for line num

		# TODO: maybe show time since last message?

	def handleConnectionMessage(self, file, line, **extra):
		match = LogAnalyzer.CONNECTION_LINE_REGEX.match(line.message)
		if match is None: return
		id = match.group('object') # pointer address of the local object for this connection
		# nb: logicalId is a GUID for each connection; each connection can have zero or one receiver and zero or one sender
		
		if id not in file['connectionIds']: 
			file['connectionIds'][id] = {'first':line.getDateTime()}
		connectionInfo = file['connectionIds'][id]
		
		# TODO: also get: 	2019-09-25 12:20:25.183 INFO  [139622782797568] - Receiver agg-correlator (component ID 6740382990692585279/6731657373788737343 [0x7efe38000b30]) is no longer slow
		
		# TODO: could summarize lifetime of each receiver separately? e.g. if tehy become slow then don;t
		# TODO; fix mix of camel case etc in titles
		
		evt = {
			'local datetime':line.getDetails()['datetimestring'],
			'local datetime object':line.getDateTime(),
			'line num':line.lineno,
			'connection ref':match.group('object'),
			'remote process name':match.group('remoteProcessName'),
		}
		
		# TODO: assert remoteIds don't change for a single connection
		
		# TODO: add something to summary about number of slow warnings and number of slow disconnections
		
		message = match.group('message')
		detailmatch = LogAnalyzer.CONNECTION_MESSAGE_IDS_REGEX.match(message)
		if detailmatch is not None:
			evt['client(physical)Id'] = detailmatch.group('remotePhysicalId')
			evt['connection(logical)Id'] = detailmatch.group('remoteLogicalId')
			if connectionInfo.get('connection(logical)Id') and (evt['connection(logical)Id'] != connectionInfo['connection(logical)Id']):
				log.warning(f"Connection information may be incorrect - connection object {evt['connection ref']} used for logical id {connectionInfo['connection(logical)Id']} and then reused for {evt['connection(logical)Id']}") 
				# TODO: this assumption doesn't hold!!! need to key off logical id instead??
			
			connectionInfo['connection(logical)Id'] = evt['connection(logical)Id']
			connectionInfo['client(physical)Id'] = evt['client(physical)Id']
			message = detailmatch.group('message')

		detailmatch = LogAnalyzer.CONNECTION_MESSAGE_ADDR_REGEX.match(message)
		if detailmatch is not None:
			connectionInfo['remotePort'] = detailmatch.group('remotePort')
			connectionInfo['host'] = detailmatch.group('host')
			assert connectionInfo['host'], detailmatch # TODO: remove
			message = detailmatch.group('message')

		if 'host# > client# > connection#' not in connectionInfo and connectionInfo.get('host') and connectionInfo.get('connection(logical)Id'):
			key = connectionInfo['host']
			hostnum = file['connectionIds'].get(key)
			if hostnum is None:
				hostnum = file['connectionIds'].get('hostnum', 0)+1
				file['connectionIds'][key] = file['connectionIds']['hostnum'] = hostnum

			key = 'P'+connectionInfo['client(physical)Id']
			processnum = file['connectionIds'].get(key)
			if processnum is None:
				processnum = file['connectionIds'].get(connectionInfo['host']+'.processnum', 0)+1
				file['connectionIds'][key] = file['connectionIds'][connectionInfo['host']+'.processnum'] = processnum

			key = 'L'+connectionInfo['connection(logical)Id']
			connectionnum = file['connectionIds'].get(key)
			if connectionnum is None:
				connectionnum = file['connectionIds'].get(connectionInfo['client(physical)Id']+'.connectionnum', 0)+1
				file['connectionIds'][key] = file['connectionIds'][connectionInfo['client(physical)Id']+'.connectionnum'] = connectionnum

			connectionInfo['host# > client# > connection#'] = f"h{hostnum:02} > cli{processnum:03} > conn{connectionnum:03}"
			
		evt['message'] = message = match.group('prefix')+' '+message
		connectionInfo['last'] = evt['local datetime object']

		if message.startswith('Receiver connected'):
			evt['connections delta'] = +1
		elif message.startswith('Receiver disconnected'):
			evt['connections delta'] = -1
			# TODO: format this delta more nicely https://stackoverflow.com/questions/538666/format-timedelta-to-string
			evt['duration secs'] = int((connectionInfo['last']-connectionInfo['first']).total_seconds())
		else:
			evt['connections delta'] = 0

		file['connectionMessages'].append(evt)


	def writeConnectionMessagesForCurrentFile(self, file):
		""" Called when the current log file is finished to write out csv/json of connection events. 
		"""
		if len(file['connectionMessages']) <= 1: return
		
		# TODO: add an isscenarioservice thingy? or a set of channels for each one
		# TODO: record number of channels, and list them (except any temproary ones); or maybe do final ones
		
		# want a summary of receivers - start, end time range; try to understand mapping between the various IDs
		#	 list of channels? max simultaneous channels?
		
		writers = [CSVStatusWriter(self)]
		if self.args.json:
			writers.append(JSONStatusWriter(self))
		for w in writers:
			w.output_file = 'receiver_connections.'+w.output_file.split('.', 1)[1]
			#log.debug('Connections: %s', file['connectionIds'])
			prevtime = None
			connections = 0
			columns = [
				'local datetime',
				'time delta secs',
				'line num',
				'host',
				'remote process name',
				'host# > client# > connection#', # a human-friendly and informative key
				'connections',
				'connections delta',
				'duration secs',
				'message',
				'connection ref',
				'client(physical)Id',
				'connection(logical)Id',
			]
			w.writeHeader(columns=columns, extraInfo=self.getMetadataDictForCurrentFile(file=file))
			for evt in file['connectionMessages']:
				# only include the more verbose messages about subscriptions etc it the JSON writer
				if evt['connections delta'] == 0 and not isinstance(w, JSONStatusWriter): continue
				
				connections += evt['connections delta']
				evt['connections'] = connections
				if prevtime:
					evt['time delta secs'] = int((evt['local datetime object']-prevtime).total_seconds())
				else:
					evt['time delta secs'] = 0
				prevtime = evt['local datetime object']
				connectionInfo = file['connectionIds'][evt['connection ref']]
				# not every line includes these, so fill in from the connection
				for k in columns:
					if k not in evt:
						evt[k] = connectionInfo.get(k)
				
				w.writeStatus(evt, missingItemValue='') # we expect many durations to be None (e.g. when connecting) and don't want to show ? for them
			w.closeFile()

	####################################################################################################################
	# Startup lines
	
	FORCE_LOG_LINE_REGEX = re.compile('(%s)'%'|'.join([
		# This big regex is for ##### (and during startup, INFO) lines which don't have a key=value structure;
		# the (?P<name>xxxx) syntax identifies named groups in the regular expression
	
		# should usually be present on recent versions:
		"Correlator, version (?P<apamaVersion>[^ ]+).*, started.",
		"Correlator, version .*, (?P<end_of_startup>running)",
		"Running on host '(?P<qualifiedHost>(?P<host>[^'.]+)[^']*)'( as user '(?P<user>[^']+)')?",
		"Running on platform '[\"]?(?P<OS>[^\"']*)[\"]?",
		"Running on CPU '(?P<cpuDetail>.*?(Intel[(]R[)] (?P<cpuShortName>.+)))'",
		"Running with process Id (?P<pid>[0-9]+)",
		"Running with (?P<physicalMemoryMB>[0-9.]+)MB of (available|physical) memory",
		"There are (?P<cpuCount>[0-9]+) CPU",
		"Component ID: (?P<componentName>.+) [(]correlator/(?P<physicalID>[0-9]+)",
		"Current UTC time: (?P<utcTime>[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]), local timezone: (?P<timezoneName>.+)",
		"Correlator command line: (?P<commandLine>.*)",
		
		# may or may not be present:
		"Java virtual machine created - (?P<jvmVersion>.*).", 
		"License File: (?P<licenseFile>[^ ]+)",
		"(?P<persistenceUpgrade>Upgrading persistent database)",
		"Correlator is restricted to (?P<licenceMaxMemoryMB>[0-9.]+) MB of resident memory",
		
		"<com.softwareag.connectivity.impl.apama.ConnectivityLoader> Loading Java class .* for plug-in (?P<connectivityPluginsJava>[^ ]+) using classpath",
		"Connectivity plug-ins: Loaded C[+][+] plugin from path (?P<connectivityPluginsCPP>.+)",
		
		'<apama-ctrl> com.apama.in_c8y.*.logStarting - Starting [^ ]+ v(?P<apamaCtrlVersion>[^ ]+)', # version pulled from manifest of apama-ctrl by Spring Boot's logStarting method

		'Shutting down correlator in response to client [(][^)]+[)] request: (?P<shutdownReason>.*)',
		
		# from the saglic section:
		" +Customer Name *: (?P<licenseCustomerName>.+)",
		" +Expiration Date *: (?P<licenseExpirationDate>.+)", # can be "Unlimited"
		" +Virtualization *: (?P<virtualizationDetected>.+)",
		]))
		
	FORCE_LOG_LINE_VALUE_LOOKUP = {
		# values to automatically convert
		'automatic':None, 
		'disabled':False, 
		'enabled':True,
		'false':False, 
		'true':True,
		'no':False, # saglic
		'yes':True,
		'** Warning input log not enabled **':None,
		'** Warning replay log not enabled **':None,
		'interpreted':None, 'compiled':'compiled(LLVM)',
		'TZ not set so using system default':None,
		'Embedded license file for Apama for Cumulocity IoT provided by Software AG':'<generic apama-ctrl license>',
		}
	def handleStartupLine(self, file, line):
		"""Called for (likely) startup lines - any ##### but also some INFO lines that occur during the startup period. """
		msg = line.message
		d = file['startupStanzas'][-1] # current (latest) startup stanza
			
		i = msg.find(' = ')
		if i > 0:
			k = msg[:i+1].strip()
			v = msg[i+2:].strip()
			v = LogAnalyzer.FORCE_LOG_LINE_VALUE_LOOKUP.get(v, v)
			if k.startswith('Input value - '): k = k[len('Input value - '):]
			k = k.lower() # best to normalize these are too variable otherwise (even between Apama versions!)
			if k in {'jvm option', 'environment variable'}:
				d.setdefault(k, []).append(v)
			else:
				d[k] = v
		else:
			match = LogAnalyzer.FORCE_LOG_LINE_REGEX.match(msg)
			if match:
				for k, v in match.groupdict().items():
					if v is None: continue
					
					if k == 'end_of_startup':
						file['inStartupStanza'] = False
						if file.get('startupContentsFile'): file.get('startupContentsFile').write(line.line+'\n')
						self.handleCompletedStartupStanza(file=file, stanza=d)
						continue
					
					if k == 'apamaVersion': # start of a new correlator log
						if d: # start of a new startup stanza - finish the old one first
							self.handleCompletedStartupStanza(file=file, stanza=d)
							d = {}
							file['startupStanzas'].append(d)
							
						file['inStartupStanza'] = True
						if 'startupContentsFile' not in file:
							file['startupContentsFile'] = io.open(f'{self.outputdir}/startup_stanza.{self.currentname}.log', 
								'w', encoding='utf-8')
							
						d['startTime'] = LogAnalyzer.formatDateTime(line.getDateTime())
						d['startLineNumber'] = line.lineno
						if len(file['startupStanzas']) > 1:
							file['startupStanzas'][-2]['endTime'] = LogAnalyzer.formatDateTime(line.getDateTime())
					
					v = LogAnalyzer.FORCE_LOG_LINE_VALUE_LOOKUP.get(v, v)
					
					if k == 'apamaCtrlVersion':
						# don't put this into the correlator startup stanza
						file['apamaCtrlVersion'] = v
						continue
					
					if k in {'connectivityPluginsJava', 'connectivityPluginsCPP'}:
						d.setdefault(k, []).append(v)
					else:
						d[k] = v

					if k == 'shutdownReason':
						d['shutdownTime'] = LogAnalyzer.formatDateTime(line.getDateTime())
					
					if k == 'utcTime':
						utcTime = datetime.datetime.strptime(v, '%Y-%m-%d %H:%M:%S')
						localTime = line.getDateTime()
						# Follow ISO 8601 and RFC 822 convention of positive offsets to East of meridian (not POSIX convention of + to the West)
						# so that utcTime + utfOffSet=local time
						utcOffsetHours = round((localTime-utcTime).total_seconds()/60.0/15.0)*(15.0/60.0)
						
						d['utcOffsetHours'] = utcOffsetHours
						offsetFractional,offsetIntegral = math.modf(abs(utcOffsetHours))
						d['utcOffset'] = f'UTC{"+" if utcOffsetHours>=0 else "-"}{int(offsetIntegral):02}:{int(60*offsetFractional):02}'

		startupContents = file.get('startupContentsFile')
		if startupContents: startupContents.write(line.line+'\n')
	
	def handleCompletedStartupStanza(self, file, stanza, **extra):
		"""Called when there's nothing more to add to this startup stanza, typically when first status line is received, or after correlator restart. 
		
		This method populates additional fields to make data easier to work with.
		
		This method is idempotent - may be called more than once. 
		"""
		if not stanza: return # nothing to do if it's missing
		
		if file.get('startupContentsFile'):
			# to avoid include extra force lines from later, stop the file after this point
			file['startupContentsFile'].close()
			file['startupContentsFile'] = None
		
		# coerse types of known float values; don't bother converting floats which we only ever need in string form
		for k in ['physicalMemoryMB', 'RLIMIT_AS', 'licenceMaxMemoryMB']:
			if stanza.get(k): 
				try:
					stanza[k] = float(stanza[k])
				except ValueError:
					pass
		
		if isinstance(stanza.get("compiler optimizations",None), str):
			if stanza["compiler optimizations"].startswith("enabled"):
				stanza["compiler optimizations"] = True
			elif stanza["compiler optimizations"].startswith("disabled"):
				stanza["compiler optimizations"] = False

		if isinstance(stanza.get("java maximum heap size",None), str):
			stanza['jvmMemoryHeapMaxMB'] = float(stanza["java maximum heap size"][:-2])
		
		stanza['cpuSummary'] = (stanza.get('cpuShortName') or stanza.get('cpuDetail') or '')\
			.replace('(R)','').replace('(TM)','').replace(' CPU ', ' ').replace('  ',' ')
		if stanza.get('cpuCount'): stanza['cpuSummary'] = f'{stanza["cpuCount"]}-core {stanza["cpuSummary"]}'
		if stanza.get('virtualizationDetected'): stanza['cpuSummary'] = 'VM with '+stanza['cpuSummary']
		if stanza.get('cgroups - available cpu(s)'):
			stanza['cpuSummary'] += f' (cgroups {stanza["cgroups - available cpu(s)"]} CPUs; {stanza.get("cgroups - cpu shares")} shares)'

		stanza['connectivity'] = sorted(list(set(stanza.get('connectivityPluginsJava',[]))))+sorted(list(set(
			[os.path.basename(path) for path in stanza.get('connectivityPluginsCPP',[])])))
		stanza['connectivity'] = [conn for conn in stanza['connectivity'] if 'codec' not in conn.lower()] # just transports
		if 'java transport config' in stanza: stanza['connectivity'] = ['Correlator-JMS']+stanza['connectivity']
		if 'distmemstore config' in stanza: stanza['connectivity'] = ['DistMemStore']+stanza['connectivity']

		# pick out binary notable features that indicate problems or useful information about how the machine is configured
		features = []
		if 'licenceMaxMemoryMB' in stanza:
			features.append('noLicenseConstrainedMode')
		elif not stanza.get('licenseFile'):
			features.append('licenseMayBeMissing!')

		if stanza.get('cgroups - maximum memory') not in {None, 'unlimited', 'unknown'}:
			stanza['cgroups - maximum memory MB'] = float(stanza['cgroups - maximum memory'].replace(' bytes','').replace(',',''))/1024.0/1024.0
			
		allocator = stanza.get('using memory allocator',None)
		if allocator not in {None, "TBB scalable allocator"}:
			features.append(f'non-default allocator: {allocator}')

		#if stanza.get('virtualizationDetected'): features.append('virtualizationDetected')
		if 'cgroups - cpu shares' in stanza: features.append('cgroupsLimits')
		if stanza.get('rlimit_core') and stanza['rlimit_core'] != 'unlimited': features.append('coreHasResourceLimit(should be unlimited!)')

		if stanza.get('loglevel','INFO')!='INFO':
			features.append(f"non-standard log level: {stanza['loglevel']}")
		if stanza.get('using epl runtime'): features.append(f"runtime: {stanza['using epl runtime']}")
		if stanza.get('persistence'): features.append('persistence')
		if stanza.get('persistenceUpgrade'): features.append('persistenceDatabaseUpgrade')
		if stanza.get('inputlog'): features.append('inputLog')
		if stanza.get('replaylog'): features.append('replayLog')
		if stanza.get('external clocking'): features.append('externalClocking')
		if not stanza.get('compiler optimizations'): features.append('optimizationsDisabled')

		if 'jvmVersion' in stanza: features.append('JVM')
		
		stanza['notableFeatures'] = features
		stanza['analyzerVersion'] = f'{__version__}/{__date__}' # always include the version of the script that generated it
		
		if stanza.get('physicalMemoryMB'): 
			maxMem = float(stanza.get('physicalMemoryMB'))
			if stanza.get('cgroups - maximum memory MB'):
				maxMem = min(maxMem, stanza['cgroups - maximum memory MB'])
			if stanza.get('licenceMaxMemoryMB'):
				maxMem = min(maxMem, stanza['licenceMaxMemoryMB'])
			
			stanza['usableMemoryMB'] = maxMem
		
		# uniquely identify this correlator
		instance = f"{stanza.get('host','?')}:{stanza.get('port','?')}"
		if stanza.get('componentName','correlator') not in {'correlator', 'defaultCorrelator'}: # ignore default name as doesn't add any information
			instance += f"[{stanza['componentName']}]"
		
		stanza['instance'] = instance

	def writeStartupStanzaSummaryForCurrentFile(self, file, **extra):
		# just in case this wasn't yet done
		self.handleCompletedStartupStanza(file=file, stanza=file['startupStanzas'][-1])

		# write the whole thing to json
		if not file['startupStanzas'][0]:
			log.warning('The ##### startup stanza was not found in this log file - please try to get the log file containing the time period when from when the correlator was first started, otherwise many problems are much harder to diagnose!')
			return
		
		if self.args.json:
			# output the full set of recovered data here
			with io.open(os.path.join(self.outputdir, f'startup_stanza.{self.currentname}.json'), 'w', encoding='utf-8') as jsonfile:
				jsonfile.write(JSONStatusWriter.toMultilineJSON(file['startupStanzas'])) # write the list of stanzas
		
	def getMetadataDictForCurrentFile(self, file):
		""" Get an ordered dictionary of additional information to be included with the header for the current file, 
		such as date, version, etc. """
		stanza = file['startupStanzas'][0] # just focus on the first one
		
		d = collections.OrderedDict()
		if 'apamaCtrlVersion' in file: d['apamaCtrlVersion'] = file['apamaCtrlVersion']
		metadataAliases = { # keys are from startupStanzas, values are aliases if needed
			'apamaVersion':None,
			'instance':None,
			'pid':None,
			'utcOffset':None,
			'utcOffsetHours':None,
			'timezoneName':'timezone',
			'OS':None,
			'physicalMemoryMB':None,
			'usableMemoryMB':None,
			'jvmMemoryHeapMaxMB':None,
			'cpuSummary':None,
			'notableFeatures':None,
			'connectivity':None,
			'analyzerVersion':None,
		}
		for k, alias in metadataAliases.items():
			v = stanza.get(k)
			if v is None: continue
			k = alias or k
			d[alias or k] = v
		d['analyzerVersion'] = f'{__version__}/{__date__}' # always include the version of the script that generated it
		return d

	def writeOverviewForAllFiles(self, **extra):
		# re-sort based on what we know now
		self.files.sort(key=lambda f: [
			# put all files for a given instance together first, then sorted by start time
			f['startupStanzas'][0].get('instance', '?'),
			f['startTime'] or datetime.datetime.min,
			# fall back on filename if not available
			f['name'],
			f['path'],
			])
		
		previousOverview = {}
		
		with io.open(os.path.join(self.outputdir, 'overview.txt'), 'w', encoding='utf-8') as out:
			for file in self.files:
				out.write(f"- {os.path.basename(file['path'])}\n")
				if not file['startTime']:
					out.write('  Not a valid Apama log file\n\n')
					continue
				out.write(f"  {self.formatDateTimeRange(file['startTime'], file['endTime'], skipPrefix=True)}\n\n")
				ss = file['startupStanzas'][0]
				if not ss:
					if 'apamaCtrlVersion' in file:
						out.write('  apama-ctrl: '+file['apamaCtrlVersion']+'\n')
					out.write('  No correlator startup stanza present in this file!\n\n')
				else:
					for stanzaNum in range(len(file['startupStanzas'])):
						ov = collections.OrderedDict() # overview sorted dict# if key ends with : then it will be prefixed
						ov['Instance:'] = f"{ss.get('instance')}" #, pid {ss.get('pid') or '?'}"
						ss = file['startupStanzas'][stanzaNum]
						
						ov['Process id:'] = f"{ss.get('pid') or '?'}"
						if stanzaNum > 0: ov['Process id:']+= f" restart #{stanzaNum+1} at {ss.get('startTime')} (line {ss['startLineNumber']})"

						ov['Apama version:'] = f"{ss.get('apamaVersion', '?')}{', apama-ctrl: '+file['apamaCtrlVersion'] if file.get('apamaCtrlVersion') else ''}; running on {ss.get('OS')}"
						ov['Log timezone:'] = f"{ss.get('utcOffset') or '?'}"+(f" ({ss.get('timezoneName')})" if ss.get('timezoneName') else '')
						if ss.get('licenseCustomerName'):
							ov['Customer:'] = f"{ss.get('licenseCustomerName')} (license expires {ss.get('licenseExpirationDate', '?')})"

						ov['Hardware:'] = f"{ss.get('cpuSummary')}"
						if ss.get('physicalMemoryMB'):
							ov['Memory:'] = f"{ss.get('physicalMemoryMB')/1024.0:0.1f} GB physical memory"
							if ss.get('usableMemoryMB')!=ss.get('physicalMemoryMB'):
								ov['Memory:'] = f"{ss.get('usableMemoryMB')/1024.0:0.1f} GB usable, "+ov['Memory:']
							if ss.get('jvmMemoryHeapMaxMB'):
								ov['Memory:'] = ov['Memory:']+f" ({ss['jvmMemoryHeapMaxMB']/1024.0:0.1f} GB Java max heap)"

						ov['Connectivity:'] = ', '.join(ss.get('connectivity', ['?']) or ['-'])
						ov['Notable:'] = ', '.join(ss.get('notableFeatures', ['?']) or ['-'])
						
						# put shutdown info last
						if 'shutdownTime' in ss: ov['Clean shutdown:'] = f"Requested at {ss['shutdownTime']} (reason: {ss['shutdownReason']})"

						# print overview of each log, but only delta from previous, since most of the time everything's the same
						anythingwritten = False
						for k in ov:
							if previousOverview.get(k)!=ov[k]:
								anythingwritten = True
								out.write('  ')
								if k.endswith(':'): out.write(f"{k:15} ")
								out.write(ov[k])
								out.write('\n')
						
						previousOverview = ov

						if anythingwritten: out.write('\n')
				# end if if startupstanza
				
				# overview statistics - just a few to give a quick at-a-glance idea; more detailed analysis should go elsewhere
				if 'status-mean' in file:
					ov = {}
					ov['errorswarns'] = f"Logged errors = {file['errorsCount']:,}, warnings = {file['warningsCount']:,}"
					ov['sendreceiverates'] = f"Received event rate mean = {file['status-mean']['rx /sec']:,.1f} /sec (max = {file['status-max']['rx /sec']:,.1f} /sec)"+\
						f", sent mean = {file['status-mean']['tx /sec']:,.1f} /sec (max = {file['status-max']['tx /sec']:,.1f} /sec)"
					usableMemoryMB = file['startupStanzas'][0].get('usableMemoryMB')
					if usableMemoryMB and 'pm=resident MB' in file['status-mean']:
						ov['memoryusage'] = f"Correlator resident memory mean = {file['status-mean']['pm=resident MB']/1024.0:,.3f} GB, "+\
							f"final = {file['status-100pc']['pm=resident MB']/1024.0:,.3f} GB, "+\
							f"JVM mean = {(file['status-mean'].get('jvm=Java MB') or 0.0)/1024.0:,.3f} GB"
						ov['memoryusagemax'] = f"Correlator resident memory max  = {file['status-max']['pm=resident MB']/1024.0:,.3f} GB "+\
							f"(={100.0*file['status-max']['pm=resident MB']/usableMemoryMB:.0f}% of {usableMemoryMB/1024.0:,.1f} GB usable), "+\
							f"at {file['status-max']['pm=resident MB.line'].getDateTimeString()} (line {file['status-max']['pm=resident MB.line'].lineno})"
					if 'is swapping' in file['status-sum']:
						ov['swapping'] = f"Swapping occurrences = "
						if file['status-sum']['is swapping'] == 0:
							ov['swapping'] += 'none'
						else:
							ov['swapping'] += f"{100.0*file['status-mean']['is swapping']:.2f}% of log file"
							ov['swapping'] += f", {self.formatDateTimeRange(file['swappingStartLine'].getDateTime(), file['swappingEndLine'].getDateTime() if 'swappingEndLine' in file else 'end')}, beginning at line {file['swappingStartLine'].lineno}"
					
					if 'iq=queued input' in file['status-max'] and 'oq=queued output' in file['status-max']:
						ov['queued'] = f"Queued input max = {file['status-max']['iq=queued input']:,}"
						if file['status-max']['iq=queued input']>0:
							ov['queued'] += f" at {file['status-max']['iq=queued input.line'].getDateTimeString()} (line {file['status-max']['iq=queued input.line'].lineno})"
						ov['queued'] += f", queued output max = {file['status-max']['oq=queued output']:,}"
						
					for k in ov:
							out.write('  ')
							out.write(ov[k])
							out.write('\n')
					out.write('\n')

			out.write(f'Generated by Apama log analyzer v{__version__}/{__date__}. \nFor more information see https://github.com/ApamaCommunity/apama-log-analyzer\n')


		with io.open(os.path.join(self.outputdir, 'overview.txt'), 'r', encoding='utf-8') as out:
			
			log.info('Overview: \n%s%s', out.read(), '' if len(self.files)==1 else 
				'NB: Values are shown only when they differ from the preceding listed log file\n')

	@staticmethod
	def formatDateTime(datetime):
		"""Format a date-time. By default milliseconds aren't included but day-of-week is. 
		"""
		if not datetime: return '<no datetime>'
		return datetime.strftime('%a %Y-%m-%d %H:%M:%S')

	@staticmethod
	def formatDateTimeRange(datetime1, datetime2, skipPrefix=False):
		"""Format a pair of date-times, with the prefix from/at. By default milliseconds aren't included but day-of-week is. 
		
		If datetime2 is a string rather than a date-time, it is included as-is. 
		"""
		prefix = 'from ' if (datetime2 and datetime2!=datetime1) else 'at '
		if skipPrefix: prefix = ''
		if (not datetime2) or datetime1==datetime2: return prefix+LogAnalyzer.formatDateTime(datetime1)
		
		if isinstance(datetime2, str):
			return f'{prefix}{LogAnalyzer.formatDateTime(datetime1)} to {datetime2}'

		delta = datetime2-datetime1
		delta = delta-datetime.timedelta(microseconds=delta.microseconds)
		
		if datetime1.date()==datetime2.date():
			formatted2 = datetime2.strftime('%H:%M:%S')
		else:
			formatted2 = LogAnalyzer.formatDateTime(datetime2)
		
		return f'{prefix}{LogAnalyzer.formatDateTime(datetime1)} to {formatted2} (={delta})'

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
	def __init__(self, analyzerFactory=LogAnalyzer):
		self.analyzerFactory = analyzerFactory

		self.argparser = argparse.ArgumentParser(description=u'Analyzes Apama correlator log files v%s/%s'%(__version__, __date__), 
			epilog=u'For Apama versions before 10.3 only the first log file contains the header section specifying version and environment information, so be sure to include that first log file otherwise critical information will be missing.')
			
		self.argparser.add_argument('--loglevel', '-l', '-v', default='INFO',
			help='Log level/verbosity for this tool')
		self.argparser.add_argument('files', metavar='FILE', nargs='+',
			help='One or more correlator log files to be analyzed; directories and glob-style expressions such as *.log are permitted. Archives such as .zip/.tar.gz/.xz will be automatically extracted.')
		self.argparser.add_argument('--output', '-o', metavar='DIR',  # later might also support zip output
			help='The directory to which output files will be written. Existing files are overwritten if it already exists.')

		self.argparser.add_argument('--json', action='store_true',
			help='Advanced/debugging option to additionally write output in JSON format suitable for processing by scripts.')

		self.argparser.add_argument('--XmaxUniqueWarnOrErrorLines', metavar='INT', default=1000, type=int,
			help='Advanced option to put an upper limit on the number of unique warn/error log lines that will be held in memory. Specify 0 to disable warn/error line tracking.')
		self.argparser.add_argument('--XmaxSampleWarnOrErrorLines', metavar='INT', default=5, type=int,
			help='Advanced option to specify how many sample warn/error log lines to include in the summary for each unique log message. Use 0 to include all matching log lines.')
		
		
	def main(self, args):
		args = self.argparser.parse_args(args)
		loglevel = getattr(logging, args.loglevel.upper())
		logging.basicConfig(format=u'%(relativeCreated)05d %(levelname)-5s - %(message)s' if loglevel == logging.DEBUG 
			else u'%(levelname)-5s - %(message)s', 
			stream=sys.stderr, level=loglevel)

		log.info('Apama log analyzer v%s/%s'%(__version__, __date__))
		
		duration = time.time()
		
		globbedpaths = []
		
		for f in args.files: # probably want to factor this out to an overridable method
			if '*' in f:
				globbed = glob.glob(f)
				if not globbed:
					raise UserError(f'No files found matching glob: {f}')
				for f in globbed: globbedpaths.append(f)
			else:
				globbedpaths.append(f)
				
		globbedpaths = [toLongPathSafe(p) for p in globbedpaths]	
		globbedpaths.sort() # best we can do until when start reading them - hopefully puts the latest one at the end
		
		if not globbedpaths: raise UserError('No log files specified')
		
		if not args.output: 
			# if not explicitly specified, create a new unique dir
			outputname = 'log_analyzer_%s'%LogAnalyzer.logFileToLogName(globbedpaths[-1]) # base it on the most recent name
			args.output = toLongPathSafe(outputname)
			i = 2
			while os.path.exists(args.output) and os.listdir(args.output): # unless it's empty
				args.output = toLongPathSafe('%s_%02d'%(outputname, i))
				i += 1
		args.output = toLongPathSafe(args.output)

		log.info('Output directory is: %s', os.path.abspath(args.output))
		assert args.output != toLongPathSafe(os.path.dirname(globbedpaths[-1])), 'Please put output into a different directory to the input log files'
		if not os.path.exists(args.output): os.makedirs(args.output)
		
		archiveextensions = {}
		for fmt, extensions, _ in shutil.get_unpack_formats():
			for ext in extensions: archiveextensions[ext] = fmt
		# add single-file archive types (i.e. without use of tar)
		import lzma, bz2, gzip
		archiveextensions['.xz'] = lzma
		archiveextensions['.bz2'] = bz2
		archiveextensions['.gzip'] = gzip
		archiveextensions['.gz'] = gzip
		
		logpaths = set()
		def raiseOnError(e):
			raise e
		def addDirectory(root):
			for (dirpath, dirnames, filenames) in os.walk(root, onerror=raiseOnError):
				if 'logs' in dirnames:
					# this looks like a project directory - don't check anything other than logs/
					log.info('Found logs/ directory; will ignore other directories under %s', dirpath)
					del dirnames[:]
					dirnames.append('logs')
					continue
				for fn in filenames:
					if (fn.endswith('.log') or fn.endswith('.out') or fn.startswith('apama-ctrl-')) and not fn.endswith('.input.log') and not fn.startswith('iaf'):
						logpaths.add(dirpath+os.sep+fn)
					else:
						log.info('Ignoring file (filename doesn\'t look like a correlator log): %s', dirpath+os.sep+fn)
			
		for p in globbedpaths:
			if p in logpaths: continue

			if os.path.isdir(p):
				addDirectory(p)
				continue
			
			if p.endswith('.7z'): raise UserError('This tool does not support .7z format; please use zip or tar.gz instead')
			
			archiveformat = next((archiveextensions[fmt] for fmt in archiveextensions if p.endswith(fmt)), None)
			if archiveformat:
				extractPath = os.path.join(args.output, 'extracted_logs', os.path.basename(os.path.splitext(p)[0]))
				log.info('Extracting %s archive: %s (to extracted_logs/ directory)', archiveformat, p)
				if isinstance(archiveformat, str):
					shutil.unpack_archive(toLongPathSafe(p), extractPath, format=archiveformat)
					addDirectory(extractPath)
				else:
					if not extractPath.endswith('.log'): extractPath += '.log'
					os.makedirs(os.path.dirname(extractPath), exist_ok=True)
					with archiveformat.open(p) as archivef:
						with io.open(extractPath, 'wb') as outputf:
							shutil.copyfileobj(archivef, outputf)
					logpaths.add(extractPath)
				continue
			
			# normal log file; do no filtering here, anything explicitly added we'll just include even if it contains .input.log or iaf
			logpaths.add(p)
		
		manager = self.analyzerFactory(args)
		manager.processFiles(sorted(list(logpaths)))

		duration = time.time()-duration
		log.info('Completed analysis in %s', (('%d seconds'%duration) if duration < 120 else ('%0.1f minutes' % (duration/60))))

		log.info('')
		log.info('If you need to request help analyzing a log file be sure to tell us: the 5-digit Apama version, the time period when the bad behaviour was observed, any ERROR/WARN messages, who is the author/expert of the EPL application code, and if possible attach the full original correlator log files (including the very first log file - which contains all the header information - and the log file during which the bad behaviour occurred). ')
		
		return 0

def toLongPathSafe(path):
	"""Converts the specified path string to a form suitable for passing to API 
	calls if it exceeds the maximum path length on this OS. 

	@param path: A path. Can be None/empty. Can contain ".." sequences. 
	
	@return: The passed-in path, absolutized, and possibly with a "\\?\" prefix added, 
	forward slashes converted to backslashes on Windows, and converted to 
	a unicode string. 
	"""
	if not path: return path
	path = os.path.abspath(path) # for consistency, always absolutize it
	if (os.name != 'nt'): return path
	
	if path[0] != path[0].upper(): path = path[0].upper()+path[1:]
	if path.startswith('\\\\?\\'): return path
	inputpath = path
	# ".." is not permitted in \\?\ paths; normpath is expensive so don't do this unless we have to
	if '.' in path: 
		path = os.path.normpath(path)
	else:
		# path is most likely to contain / so more efficient to conditionalize this 
		path = path.replace('/','\\')
		if '\\\\' in path:
		# consecutive \ separators are not permitted in \\?\ paths
			path = path.replace('\\\\','\\')

	if path.startswith(u'\\\\'): 
		path = u'\\\\?\\UNC\\'+path.lstrip('\\') # \\?\UNC\server\share
	else:
		path = u'\\\\?\\'+path
	return path
orig_io_open = io.open
def io_open_patched(path, *args, **kwargs):
	return orig_io_open(toLongPathSafe(path), *args, **kwargs)
io.open = io_open_patched

if __name__ == "__main__":
	try:
		sys.exit(LogAnalyzerTool().main(sys.argv[1:]))
	except UserError as ex:
		sys.stderr.write(f'ERROR - {ex}\n')
		sys.exit(100)
