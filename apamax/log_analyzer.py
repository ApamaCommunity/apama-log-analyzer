#!/usr/bin/env python3

""" This is a Python 3 script for analyzing Apama correlator (and apama-ctrl) log files. 

It extracts and summarizes information from status lines and other log messages.


Copyright (c) 2019-2020 Software AG, Darmstadt, Germany and/or its licensors

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
file except in compliance with the License. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. 
See the License for the specific language governing permissions and limitations under the License.

These tools are provided as-is and without warranty or support. They do not constitute part of the Software AG product suite. Users are free to use, fork and modify them, subject to the license agreement. 

"""

__date__ = '2020-07-10' 
__version__ = '3.8.dev/'+__date__
__author__ = "Apama community"
__license__ = "Apache 2.0"

import logging, os, io, argparse, re, time, sys, collections, datetime, calendar
import json
import glob
import math
import shutil
import locale
import xml.sax.saxutils
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
	('=rx /sec',None),
	('=tx /sec',None),
	('=rt /sec',None),

	('=rx /sec 1min avg',None),
	('=tx /sec 1min avg',None),
	('=rt /sec 1min avg',None),

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
If value is None, column will be ignored. If key starts with "=", it's a generated field. 
Items listed here but not in the status line will be ignored; 
Extra items in status line but not here will be added.

Use | chars to break up sections of related columns
"""

def escapetext(text):
	"""HTML/XML escaping for text. """
	if not isinstance(text, str): text = str(text)
	return xml.sax.saxutils.escape(text).encode('ascii', 'xmlcharrefreplace').decode('ascii')
def escapeattr(text): # attributes, including quoting
	if not isinstance(text, str): text = str(text)
	return xml.sax.saxutils.quoteattr(text).encode('ascii', 'xmlcharrefreplace').decode('ascii')

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
			if columnDisplayName.endswith('local datetime'):
				return item[:item.find('.')] # strip off seconds as excel misformats it if present
			if item in [True,False]: return str(item).upper()
			if isinstance(item, float) and item.is_integer and abs(item)>=1000.0:
				item = int(item) # don't show decimal points for large floats like 7000.0, for consistency with smaller values like 7 when shown in excel (weird excel rules)
			if isinstance(item, int):
				if columnDisplayName.endswith('epoch secs'):
					return f'{item}'
				return f'{item:,}'
			if isinstance(item, float):
				return f'{item:,.2f}' # deliberately make it different from the 3 we use for grouping e.g. mem usage kb->MB
			if isinstance(item, list): # e.g. for notableFeatures list
				return '; '.join(item)
			return str(item)
		except Exception as ex:
			raise Exception(f'Failed to format "{columnDisplayName}" value {repr(item)}: {ex}')
	
	def writeCSVLine(self, items):
		"""
		Writes a line of CSV output, with appropriate escaping. 
		
		@param items: a list of strings, integer or floats to be written to the file. 
		Escaping will be performed
		"""
		# nb if we output an integer as a string and it has 14-15 digits (e.g. a connection id) excel will helpfully convert it to an imprecise float - so quote it
		items = ['%s"%s"'%('=' if i.isdigit() else '', i.replace('"', '""')) if (',' in i or '"' in i or (i.isdigit() and len(i)>14) ) else i for i in items]
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


class ChartDataWriter(BaseWriter):
	"""A special multi-file writer for the temp files we use to generate HTML graphs."""
	def writeHeader(self, columns=None, extraInfo=None, **extra):
		self.closeFile()
		
		tmp = os.path.join(self.manager.outputdir, 'tmp')
		os.makedirs(tmp, exist_ok=True)
		
		assert not getattr(self, '__files', None), self.files # already opened somehow - shouldn't happen
		self.__files = {
			c:io.open(tmp+f"/{c}_{self.manager.currentname}.json", 'w', encoding='utf-8')
			for c in self.manager.CHARTS
		}
		self.prependComma = False
		self.chartKeys = [(
			chartname, 
			# key, scaling values (to scale MB values back to up to bytes for correct display in chart
			[(key, 1*1024.0*1024.0 if key.endswith(' MB') else 1) for key in options['labels']], 
			options.get('logscale')
			) for chartname, options in self.manager.CHARTS.items()]

	@staticmethod
	def formatItem(key, value, scalingfactor):
		if key == 'is swapping' and value == 0: value = None
		if value is None: return 'null'
		# assume it's a number; try to find a concise representation to keep the HTML small
		value = value*scalingfactor
		if value == 0: return '0'
		try:
			if value > 100: return f'{value:.0f}'
		except TypeError:
			pass # occasionally the value will be a user-defined string in which case ">" operator won't work
		return str(value)
	
	def writeStatus(self, status=None, line=None, **extra):
		files = self.__files
		if self.prependComma: 
			prefix = ',\n'
		else:
			prefix = '\n'
			self.prependComma = True
		# format the data as a JavaScript object; use local time so it formats nicely 
		# (and hoping that there's no DST differences in display locale vs generated locale)
		
		dt = line.getDateTime()
		# don't bother with milliseconds, not useful
		prefix += f'[new Date({dt.year},{dt.month-1},{dt.day},{dt.hour},{dt.minute},{dt.second}),'
		
		formatItem = ChartDataWriter.formatItem
		
		# could invoke json to convert these values to valid JSON but seems like overkill
		# don't think non-numeric values are possible, so not handling for now
		for chartname, keys_and_scaling_values, logscale in self.chartKeys:
			# assume these are all numbers
			# for avoid confusing chart library, can't allow any zero values
			#if logscale: values = [v if v=='null' or v>0 else 0.0001 for v in values]
			
			files[chartname].write(prefix+','.join(formatItem(key, status.get(key, None), scaling) for (key, scaling) in keys_and_scaling_values)+']')
				
	def closeFile(self):
		for f in getattr(self, '__files',{}).values():
			f.close()
		self.__files = None

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
		
		self.writers = [CSVStatusWriter(self), ChartDataWriter(self)]
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
		
		skipto = int(self.currentpathbytes*self.args.skip/100) if self.args.skip else None
		
		lastprogressupdate = time.time()
		
		with io.open(self.currentpath, encoding='utf-8', errors='replace') as f:
			self.__currentfilehandle = f
			charcount = 0
			lineno = 0
			previousLine = None
			startTime = None
			stripPrefix = None
			for line in f:
				lineno += 1
				charcount += len(line)
				
				if self.currentpathbytes < 10*1000 or lineno % 1000 == 0: # don't do it too often for large files
					# can't use tell() on a text file (without inefficiency), so assume 1 byte per char (usually true for ascii) as a rough heuristic
					percent = 100.0*charcount / (self.currentpathbytes or -1) # (-1 is to avoid div by zero when we're testing against a fake)
					for threshold in [25, 50, 75]:
						if percent >= threshold and lastpercent < threshold:
							self.handleFilePercentComplete(file=file, percent=threshold)
							lastpercent = threshold
					if time.time()-lastprogressupdate > 5:
						log.info(f'   {percent:0.1f}% through this file')
						lastprogressupdate = time.time()
				
				self.currentlineno = lineno
				
				line = line.rstrip()
				
				if len(line)==0: continue # blank lines aren't useful
				
				if lineno <= 4: # for performance, only bother to check the first few lines
					m = re.match('([A-Za-z][A-Za-z0-9_.-]+ +[|] )[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]', line)
					if m: stripPrefix = m.group(1)
				# strip off docker names
				if stripPrefix is not None and line.startswith(stripPrefix): 
					line = line[len(stripPrefix):]
				
				try:
					logline = LogLine(line, lineno)
					# skip once we've got past the startup stanza - first status line is a good way to detect when that's happened
					if skipto and logline.message.startswith(('Correlator Status: ', 'Status: sm')):
						log.info(f'Skipping first {skipto:,} bytes of file (found status at line {lineno} but no startup stanza)')
						f.seek(skipto)
						skipto = None
						lineno = 100000000-1 # set this to a sentinel value to alert people these are numbers relative to start of skip not absolute
						continue
					if startTime is None and logline.level is not None and not skipto: 
						startTime = logline.getDateTime()
						file['startTime'] = startTime
					
					if self.handleLine(file=file, line=logline, previousLine=previousLine) != LogAnalyzer.DONT_UPDATE_PREVIOUS_LINE:
						previousLine = logline
					if logline.level is not None: finalLineWithTimestamp = logline
					
					if skipto and file['startupStanzas'][0] and not file['inStartupStanza']:
						log.info(f'Skipping first {skipto:,} bytes of file (now startup stanza has been read)')
						f.seek(skipto)
						skipto = None
						lineno = 100000000-1 # set this to a sentinel value to alert people these are numbers relative to start of skip not absolute
						continue
					
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
		self.userStatus = {}
		file['errorsCount'] = file['warningsCount'] = 0
		
		# for handleAnnotatedStatusDict summarization
		file['status-min'] = file['status-max'] = file['status-sum'] = \
			file['status-0pc'] = file['status-25pc'] = file['status-50pc'] = file['status-75pc'] = file['status-100pc'] = None
		self.previousAnnotatedStatus = None # annotated status
		file['totalStatusLinesInFile'] = 0
		
		file['startupStanzas'] = [{}]
		file['annotations'] = []
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

		for (userStatusPrefix, userStatusPrefixAfterBracket), userStatus in self.args.userStatusLines.items():
			if m.startswith(userStatusPrefix):
				if userStatusPrefixAfterBracket is not None: # special handling of [n] values
					if userStatusPrefixAfterBracket not in m: continue
				self.handleRawStatusLine(file=file, line=line, userStatus=userStatus)
				break
			
		if level == 'W':
			if m.startswith('Receiver '):
				self.handleConnectionMessage(file, line)
			
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
			'Receiver ',
			# don't really need these messages, they don't contain extra info we can't get from the other ones
			#'The receiver ',
			#'Blocking receiver ',
			)):
				self.handleConnectionMessage(file, line)
	
	def handleRawStatusLine(self, file, line, userStatus=None, **extra):
		"""
		Handles a raw status line which may be a correlator status line or a user-defined one
		"""
		m = line.message
		d = collections.OrderedDict()
		d['datetime'] = line.getDetails()['datetimestring']
		
		# TODO: fix the epoch calculation; treating this as UTC isn't correct since it probably isn't
		d['epoch secs'] = line.getDateTime().replace(tzinfo=datetime.timezone.utc).timestamp()

		d['line num'] = line.lineno
				
		i = m.index(':')+2
		mlen = len(m)
		while i < mlen:
			# cope with space-delimited values and/or strings
			key = ''
			while i < mlen and m[i]!='=':
				key+= m[i]
				i += 1
			if i == mlen:
				# this can happen if (mysteriously) a line break character is missing at end of status line (seen in 10.3.3); better to limp on rather than throwing; but ignore the <...> message we include at the end of JMS status lines
				(log.debug if (key.startswith('<') and key.endswith('>')) else log.warning)(f'Ignoring the rest of status log line {line.lineno}; expected "=" but found end of line: "{key}"')
				break # don't ignore the bits we already parsed out successfully
			assert m[i] == '=', (m, repr(m[i]))
			i+=1
			if m[i]=='"':
				endchar = '"'
				i+=1
			else:
				endchar = ' '
			val = ''
			while i < mlen and m[i] != endchar:
				if endchar != '"' or m[i] != ',': # if not a string, suppress thousands character
					val += m[i]
				i+=1
			if endchar != '"':
				try:
					if val.endswith('%') and val[:-1].replace('.','').isdigit(): val = val[:-1] # for user-defined % values which would otherwise not be graphable
					if '.' in val:
						val = float(val)
					else:
						val = int(val)
				except Exception:
					pass
			d[key] = val
			while i < mlen and m[i] in {' ', '"'}: i+=1
		if not d: return
		
		#log.debug('Extracted status line %s: %s', d)
		if userStatus is not None:
			# must do namespacing here since there could be multiple user-defined statuses and we don't want them to clash
			prefix = userStatus['keyPrefix']
			for k, alias in userStatus['key:alias'].items():
				if k in d:
					self.userStatus[prefix+(alias or k)] = d[k]
		else:
			self.handleRawStatusDict(file=file, line=line, status=d)	
		
	def handleRawStatusDict(self, file, line, status=None, **extra):
		"""
		Accepts a raw correlator status dictionary and converts it to an annotated status 
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
				
				# now add on any user-defined status keys; always add these regardless of whether they're yet set, 
				# since they may come from EPL code that hasn't been injected yet and we can't change the columns later
				for user in self.args.userStatusLines.values():
					for k, alias in user['key:alias'].items(): # aliasing for user-defined status lines happens in handleRawStatusLine
						k = user['keyPrefix']+(alias or k)
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
		
		if (not previousStatus) or (previousStatus['restarts'] != len(file['startupStanzas'])): 
			if file['startupStanzas'][-1].get('startTime'): # this is the only place we can add the annotation given we must associated it with a timestamp that's in the data series
				file['annotations'].append({'x': line.getDateTime(), 'shortText':'start', 'width':40, 
					'text': f"Correlator process {'started' if len(file['startupStanzas'])==1 else 'restart #%s'%(len(file['startupStanzas'])-1)}"})

		
		if previousStatus is None:
			if file['startTime'] is not None:
				secsSinceLast = status['epoch secs']-file['startTime'].replace(tzinfo=datetime.timezone.utc).timestamp()
			else:
				secsSinceLast = -1 # hopefully won't happen
		else:
			secsSinceLast = seconds-previousStatus['epoch secs']
			# reset everything when there's a restart, else we'll end up with a blip of negative event rates and other stats may be wrong too due to incorrect secsSinceLast
			if previousStatus['restarts'] != len(file['startupStanzas']): 
				previousStatus = None # to avoid getting negative values

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

				elif k == '=errors /sec':
					val = (file['errorsCount']-previousStatus['errors'])/secsSinceLast
				elif k == '=warns /sec':
					val = (file['warningsCount']-previousStatus['warns'])/secsSinceLast

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
				elif k.endswith(' avg'): continue # handled below
				elif k == '=jvm delta MB':
					try:
						val = (status['jvm']-previousStatus['jvm'])/1024.0
					except KeyError: # not present in all Apama versions
						continue
				else:
					assert False, 'Unknown generated key: %s'%k
			else:
				val = status.get(k, None)
				if val is None: val = self.userStatus.get(k, None)
				if display[k] in ['pm=resident MB', 'vm=virtual MB'] and val is not None:
					val = val/1024.0 # kb to MB

			d[display[k]] = val

		# moving averages
		avgSecsPerWindow = 60 # approx 12 points if once per 5 secs = 1 minute
		avgkeys = ['rx /sec', 'tx /sec', 'rt /sec']
		try:
			windows = file['status-windows']
		except KeyError:
			windows = {k: collections.deque() for k in avgkeys}
			file['status-windows'] = windows
		for avgk in avgkeys:
			win = windows[avgk]
			win.append(d[avgk])
			# expire old items (heuristically based on most recent secsSinceLast); special-case to avoid having less than 2 items in window 
			# for case where status lines are coming less than frequently once per avgSecsPerWindow
			while win and secsSinceLast>0 and (len(win) > avgSecsPerWindow/secsSinceLast) and len(win)>=2:
				win.popleft()
			d[avgk+' 1min avg'] = sum(win)/len(win) if len(win) > 0 else 0.0

		self.handleAnnotatedStatusDict(file=file, line=line, status=d)
		status['restarts'] = len(file['startupStanzas'])
		self.previousRawStatus = status # both raw and annotated values

	def handleAnnotatedStatusDict(self, file, line, status, **extra):
		"""
		@param line: There may be multiple lines associated with this status; this is typically the first one
		"""
		for w in self.writers:
			w.writeStatus(status=status, line=line)
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
		file['totalStatusLinesInFile'] += 1
		for k, v in status.items():
			if v is None or isinstance(v, str): continue
			try:
				if v < file['status-min'][k]: file['status-min'][k] = v
			except Exception: # this happens for user-defined statuses which weren't initialized right at the start
				if file['status-min'][k] is None:
					file['status-min'][k] = v
					file['status-max'][k] = v
					file['status-sum'][k] = 0
				else: raise

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
		totalStatusLinesInFile = file['totalStatusLinesInFile']
		file['showCharts'] = True #totalStatusLinesInFile > 10 # no point cluttering the output for tiny files
		if totalStatusLinesInFile < 2 or (not self.previousAnnotatedStatus) or (not file.get('status-100pc')):
			log.warning('%d status line(s) found in %s; not enough to analyze', totalStatusLinesInFile, self.currentname)
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

			v = v / float(totalStatusLinesInFile) # force a floating point division
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
						if (isinstance(status[k], str) or k in ['seconds', 'line num', 'interval secs'] or k.endswith('.line')
								or status[k] is None or prev[k] is None or isinstance(prev[k], str)):
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

	WARN_ERROR_NORMALIZATION_REGEX = re.compile('(%s)'%'|'.join([
		# hexadecimal pointer address from an slow consumer message
		r'\[[0-9a-fA-Fx][0-9a-fA-Fx][0-9a-fA-Fx][0-9a-fA-Fx][0-9a-fA-Fx][0-9a-fA-Fx]+\]',
		# numbers
		'[0-9][0-9.]*',
		# the beginning of an event string
		'[.][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]+[(].*',
		]))
	@staticmethod
	def __replaceWarnOrErrorWithSub(msg):
		msg = msg.group(1)
		if '(' in msg: 
			return msg[:msg.find('(')]+'___'
		return '___'
	def handleWarnOrError(self, file, isError, line, **extra):
		if isError:
			file['errorsCount'] += 1
			tracker = self.errors
		else:
			file['warningsCount'] += 1
			tracker = self.warns
		
		XmaxUniqueWarnOrErrorLines = self.args.XmaxUniqueWarnOrErrorLines
		
		normmsg = msg = line.message
		# heuristically normalize so we can group potentially similar messages together
		if normmsg.find(':',80)>0: normmsg = normmsg[:normmsg.find(':', 80)+1]+'___'
		normmsg = LogAnalyzer.WARN_ERROR_NORMALIZATION_REGEX.sub(self.__replaceWarnOrErrorWithSub, normmsg)
		
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
					f.write(f"{file[f'{kind}Count']:,} {kind} in {file['name']}\n")
				f.write("\n")

				f.write(f'Generated by Apama log analyzer v{__version__}.\n\n')

				if self.args.XmaxUniqueWarnOrErrorLines>0 and len(tracker)==self.args.XmaxUniqueWarnOrErrorLines:
					f.write(f'WARNING: Some messages are NOT included in this file due to the XmaxUniqueWarnOrErrorLines limit of {self.args.XmaxUniqueWarnOrErrorLines}\n\n')
					log.warning(f'Some messages are NOT included in the {kind} file due to the XmaxUniqueWarnOrErrorLines limit of {self.args.XmaxUniqueWarnOrErrorLines})')

				f.write(f"Summary of {kind}, sorted by normalized message, with number of occurrences of that message indicated by '<OCCURRENCES>x': \n\n")
				
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

					prefix = f"--- {totalcount:,}x: "
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
								f.write(f"      {byfile['count']:,}x {self.formatDateTimeRange(byfile['first'].getDateTime(), byfile['last'].getDateTime())} in {self.logFileToLogName(logfile)}\n")

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
	
		# hack: hope/assume that pointer addresses are always prefixed with 00 on linux 
		# this regex gets the objectAddr in all cases, and for "slow" messages also the logical/physical ids; for other 
		# messages we separately use CONNECTION_MESSAGE_IDS_REGEX to get those
		r"^(?P<prefix>Receiver|Connected to receiver|Blocking receiver) (?P<remoteProcessName>.+) [(]"+\
			"(component ID (?P<remotePhysicalId>[0-9]+)/(?P<remoteLogicalId>[0-9]+) \[)?"+\
			"(?P<objectAddr>(0x|00)[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)\]?[)] (?P<message>.+)"
		)
		
	def handleConnectionMessage(self, file, line, **extra):
		match = LogAnalyzer.CONNECTION_LINE_REGEX.match(line.message)
		if match is None: return
		
		# nb: logicalId is a GUID for each connection; each connection can have zero or one receiver and zero or one sender
		
		evt = {
			'local datetime':line.getDetails()['datetimestring'],
			'local datetime object':line.getDateTime(),
			'line num':line.lineno,
			'connection ref':match.group('objectAddr'),
			'remote process name':match.group('remoteProcessName'),
			
		}
		
		message = match.group('message')
		if match.group('remotePhysicalId'):
			evt['client(physical)Id'] = match.group('remotePhysicalId')
			evt['connection(logical)Id'] = match.group('remoteLogicalId')		
		else:
			detailmatch = LogAnalyzer.CONNECTION_MESSAGE_IDS_REGEX.match(message)
			if detailmatch is not None:
				evt['client(physical)Id'] = detailmatch.group('remotePhysicalId')
				evt['connection(logical)Id'] = detailmatch.group('remoteLogicalId')
				message = detailmatch.group('message')

		# the logical id is the safest thing to key this off, but fall back to objectAddr if needed (though those can repeat, so be careful!)
		# NB: with this algorithm there's a small race where if we first see a message with objectAddr and no logical id 
		# we could fail it match it up later with the correct connection (since really we're using logical id for keying these), 
		# but that's a relatively unlikely case and doesn't matter too much since it's only the subscription messages that don't have the logical id
		newconnectioninfo = {'first':line.getDateTime(), '__slow periods':0}
		if 'connection(logical)Id' in evt:
			key = 'connection(logical)Id_'+evt['connection(logical)Id']
			if key in file['connectionIds']:
				connectionInfo = file['connectionIds'][key]
			else:
				file['connectionIds'][key] = connectionInfo = newconnectioninfo 
		else:
			key = 'connectionAddr_'+evt['connection ref']
			if key in file['connectionIds']:
				connectionInfo = file['connectionIds'][key]
				# if we have the proper ids, add them here
				if 'client(physical)Id' in connectionInfo:
					evt['client(physical)Id'] = connectionInfo['client(physical)Id']
					evt['connection(logical)Id'] = connectionInfo['connection(logical)Id']
			else:
				connectionInfo = newconnectioninfo 
		# keep the most recent connection add updated regardless, since we might need it to handle a message that doesn't have this
		file['connectionIds']['connectionAddr_'+evt['connection ref']] = connectionInfo
		evt['connectionInfo'] = connectionInfo
		
		if 'connection(logical)Id' in evt:
			connectionInfo['connection(logical)Id'] = evt['connection(logical)Id']
			connectionInfo['client(physical)Id'] = evt['client(physical)Id']

		detailmatch = LogAnalyzer.CONNECTION_MESSAGE_ADDR_REGEX.match(message)
		if detailmatch is not None:
			connectionInfo['remotePort'] = detailmatch.group('remotePort')
			connectionInfo['host'] = detailmatch.group('host')
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
			
		message = match.group('prefix')+' '+message
		#if ':' in message:
		#	message, evt['message detail'] = message.split(': ', 1)
		#elif '(' in message:
		#	message, evt['message detail'] = message.split('(', 1)
		#	evt['message detail']='('+evt['message detail']
		evt['message'] = message
		connectionInfo['last'] = evt['local datetime object']

		if message.startswith('Receiver connected'):
			evt['connections delta'] = +1
		elif message.startswith('Receiver disconnected'):
			evt['connections delta'] = -1
			# TODO: format this delta more nicely https://stackoverflow.com/questions/538666/format-timedelta-to-string
			evt['duration secs'] = int((connectionInfo['last']-connectionInfo['first']).total_seconds())
			if connectionInfo['__slow periods']: # final value is useful when disconnecting
				evt['slow periods'] = connectionInfo['__slow periods']
		else:
			evt['connections delta'] = 0
		
		if message.startswith('Receiver is slow'):
			connectionInfo['__slow periods'] += 1
			evt['slow periods'] = connectionInfo['__slow periods']
		
		if 'com.apama.scenario' in message: connectionInfo['scenario service'] = True

		file['connectionMessages'].append(evt)


	def writeConnectionMessagesForCurrentFile(self, file):
		""" Called when the current log file is finished to write out csv/json of connection events. 
		"""
		if len(file['connectionMessages']) <= 1: return
		
		# Extensions: could track channels, record #channels for each one, maybe list them
		
		# TODO: could display the duration better

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
				'slow periods',
				'message',
				'scenario service',
				'connection ref',
				'client(physical)Id',
				'connection(logical)Id',
			]
			w.writeHeader(columns=columns, extraInfo=self.getMetadataDictForCurrentFile(file=file))
			for evt in file['connectionMessages']:
				evt = dict(evt)
				# only include the more verbose messages about subscriptions etc in the JSON writer
				if evt['message'].startswith((
					'Receiver initially subscribed to ',
					'Receiver unsubscribed from ',
					'Receiver added subscriptions to ',
				)) and not isinstance(w, JSONStatusWriter): continue
				
				assert 'connections delta' in evt, evt
				connections += evt['connections delta']
				evt['connections'] = connections
				if prevtime:
					evt['time delta secs'] = int((evt['local datetime object']-prevtime).total_seconds())
				else:
					evt['time delta secs'] = 0
				prevtime = evt['local datetime object']
				# not every line includes these, so fill in from the connection
				for k in columns:
					if k not in evt:
						evt[k] = evt['connectionInfo'].get(k)
						
				if evt.get('connections delta') == 0: del evt['connections delta'] # makes the csv easier to read
				
				del evt['connectionInfo'] # no point stashing this in the json
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
		stanza['analyzerVersion'] = f'{__version__}' # always include the version of the script that generated it
		
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
		d['analyzerVersion'] = f'{__version__}' # always include the version of the script that generated it
		return d

	def writeOverviewForAllFiles(self, **extra):
		# re-sort based on what we know now
		
		# use this to establish if we have more than one instance present
		instances = set(f['startupStanzas'][0].get('instance', '?') for f in self.files)
		instances.discard('?')
		
		self.files.sort(key=lambda f: [
			# put all files for a given instance together first (since relative start time of each correlator isn't 
			# stable across restart), then sorted by start time
			# (but if we don't know the instance for a file, inherit from the earliest one, otherwise we end up putting 
			# files WITH a startup stanza at the end, which is the opposite of what's most desirable)
			None if len(instances)< 2 else f['startupStanzas'][0].get('instance','?'),
			f['startTime'] or datetime.datetime.min,
			# fall back on filename if not available
			f['name'],
			f['path'],
			])
		previousOverview = {}
		
		# assign a human-friendly index for each file since sometimes the actual log names are hard for humans to differentiate quickly
		for i in range(len(self.files)):
			self.files[i]['index'] = f'#{i+1:02}'
		
		self.overviewHTML = ''
		
		with io.open(os.path.join(self.outputdir, 'overview.txt'), 'w', encoding='utf-8') as out:
			# produce this in both txt and HTML format
			def write(html):
				self.overviewHTML += html
				# strip out HTML tags and un-escape named entities
				if html.startswith('<li>'): html = '- '+html # textual equivalent
				txt = xml.sax.saxutils.unescape(re.sub('<[^>]+>', '', html))
				txt = txt.replace(' ...\n', '\n') # remove <a>... links 
				out.write(txt)
			def writeln(html):
				write(html.replace('\n','<br>\n')+'<br>\n')
			def v(val, cls='overview-value', fmt=None): # values are escaped then put into a span for formatting
				if fmt: val = ('{:'+fmt+'}').format(val)
				return f'<span class="{cls}">{escapetext(val)}</span>'

			write('<ul>')
			for file in self.files:
				writeln(f"<li>{file['index']} {v(os.path.basename(file['path']))}")
				if not file['startTime']:
					writeln('  Not a valid Apama log file\n</li>')
					continue
				writeln(f"  {v(self.formatDateTimeRange(file['startTime'], file['endTime'], skipPrefix=True), cls='overview-timerange')}\n")
				ss = file['startupStanzas'][0]
				if not ss:
					if 'apamaCtrlVersion' in file:
						writeln(f"  apama-ctrl: {v(file['apamaCtrlVersion'])}")
					writeln('  '+v('No correlator startup stanza present in this file!', cls='overview-warning')+'\n')
				else:
					for stanzaNum in range(len(file['startupStanzas'])):
						ov = collections.OrderedDict() # overview sorted dict# if key ends with : then it will be prefixed
						ov['Instance:'] = f"{v(ss.get('instance'), cls='overview-instance')}" #, pid {ss.get('pid') or '?'}"
						ss = file['startupStanzas'][stanzaNum]
						
						ov['Process id:'] = f"{v(ss.get('pid') or '?',cls='overview-pid overview-value')}"
						if stanzaNum > 0: ov['Process id:']+= " "+v(f"restart #{stanzaNum}")+f" at {v(ss.get('startTime'))} (line {ss['startLineNumber']})"

						ov['Apama version:'] = f"{v(ss.get('apamaVersion', '?'))}{', apama-ctrl: '+v(file['apamaCtrlVersion']) if file.get('apamaCtrlVersion') else ''}; running on {v(ss.get('OS'))}"
						ov['Log timezone:'] = f"{v(ss.get('utcOffset') or '?')}"+(f" ({v(ss.get('timezoneName'))})" if ss.get('timezoneName') else '')
						if ss.get('licenseCustomerName'):
							ov['Customer:'] = f"{v(ss.get('licenseCustomerName'))} (license expires {v(ss.get('licenseExpirationDate', '?'))})"

						ov['Hardware:'] = f"{v(ss.get('cpuSummary'))}"
						if ss.get('physicalMemoryMB'):
							ov['Memory:'] = v(f"{ss.get('physicalMemoryMB')/1024.0:0.1f} GB")+" physical memory"
							if ss.get('usableMemoryMB')!=ss.get('physicalMemoryMB'):
								ov['Memory:'] = v(f"{ss.get('usableMemoryMB')/1024.0:0.1f} GB")+" usable, "+ov['Memory:']
							if ss.get('jvmMemoryHeapMaxMB'):
								ov['Memory:'] = ov['Memory:']+" ("+v(f"{ss['jvmMemoryHeapMaxMB']/1024.0:0.1f} GB")+" Java max heap)"

						ov['Connectivity:'] = v(', '.join(ss.get('connectivity', ['?']) or ['-']))
						ov['Notable:'] = v(', '.join(ss.get('notableFeatures', ['?']) or ['-']))
						
						# put shutdown info last
						if 'shutdownTime' in ss: ov['Clean shutdown:'] = f"Requested at {v(ss['shutdownTime'])} (reason: {v(ss['shutdownReason'])})"

						# print overview of each log, but only delta from previous, since most of the time everything's the same
						anythingwritten = False
						for k in ov:
							if previousOverview.get(k)!=ov[k]:
								anythingwritten = True
								write('  ')
								if k.endswith(':'): write(f"{k:15} ")
								write(ov[k])
								writeln('')
						
						previousOverview = ov

						if anythingwritten: writeln('')
				# end if if startupstanza
				
				# overview statistics - just a few to give a quick at-a-glance idea; more detailed analysis should go elsewhere
				if 'status-mean' in file:
					
					def lowKeyChartLink(chartid):
						# generate a fragment link to jump to the chart, but keep it low-key with a short "..." since we want to the focus 
						# to be on the text here not the blue/underlined links
						return f" <a href='#chart_{self.getChartId(chartid, file)}'>...</a>"
					
					ov = {}
					ov['errorswarns'] = f"Logged errors = {v(file['errorsCount'],fmt=',')}, warnings = {v(file['warningsCount'], fmt=',')}"
					
					if file['errorsCount']+file['warningsCount'] > 0:
						ov['errorswarns'] += " (see "+', '.join([f"<a href='{linkedfile}'>{linkedfile}</a>" for linkedfile in ['logged_errors.txt', 'logged_warnings.txt'] if os.path.exists(self.outputdir+'/'+linkedfile)])+")"
						
					ov['sendreceiverates'] = f"Received event rate mean = {v(file['status-mean']['rx /sec'],fmt=',.1f')} /sec (max = {v(file['status-max']['rx /sec'],fmt=',.1f')} /sec)"+\
						f", sent mean = {v(file['status-mean']['tx /sec'],fmt=',.1f')} /sec (max = {v(file['status-max']['tx /sec'],fmt=',.1f')} /sec)"+\
						lowKeyChartLink('rates')
						
					usableMemoryMB = file['startupStanzas'][0].get('usableMemoryMB')
					if 'pm=resident MB' in file['status-mean']:
						ov['memoryusage'] = "Correlator resident memory mean = "+v(f"{file['status-mean']['pm=resident MB']/1024.0:,.3f} GB")+", "+\
							"final = "+v(f"{file['status-100pc']['pm=resident MB']/1024.0:,.3f} GB")+", "+\
							"JVM mean = "+v(f"{(file['status-mean'].get('jvm=Java MB') or 0.0)/1024.0:,.3f} GB")
						
						ov['memoryusagemax'] = "Correlator resident memory max  = "+v(f"{file['status-max']['pm=resident MB']/1024.0:,.3f} GB")+" "
						if usableMemoryMB:
							ov['memoryusagemax'] += "(="+v(f"{100.0*file['status-max']['pm=resident MB']/usableMemoryMB:.0f}%")+\
								" of "+v(f"{usableMemoryMB/1024.0:,.1f} GB")+" usable), "
						ov['memoryusagemax'] += f"at {v(file['status-max']['pm=resident MB.line'].getDateTimeString())} (line {file['status-max']['pm=resident MB.line'].lineno})"+lowKeyChartLink('memory')
						
					if 'is swapping' in file['status-sum']:
						ov['swapping'] = f"Swapping occurrences = "
						if file['status-sum']['is swapping'] == 0:
							ov['swapping'] += 'none'
						else:
							ov['swapping'] += v(f"{100.0*file['status-mean']['is swapping']:.2f}%", cls='overview-swapping')+" of log file"
							ov['swapping'] += f", {v(self.formatDateTimeRange(file['swappingStartLine'].getDateTime(), file['swappingEndLine'].getDateTime() if 'swappingEndLine' in file else 'end'))}, beginning at line {file['swappingStartLine'].lineno}"+lowKeyChartLink('memory')
					
					if 'iq=queued input' in file['status-max'] and 'oq=queued output' in file['status-max']:
						ov['queued'] = f"Queued input max = {v(file['status-max']['iq=queued input'],fmt=',')}"
						if file['status-max']['iq=queued input']>0:
							ov['queued'] += f" at {v(file['status-max']['iq=queued input.line'].getDateTimeString())} (line {file['status-max']['iq=queued input.line'].lineno})"
						ov['queued'] += f", queued output max = {v(file['status-max']['oq=queued output'],fmt=',')}"+lowKeyChartLink('queues')
					
					slowevents = [evt for evt in file['connectionMessages'] if (
						evt.get('connections delta')==-1 and 'slow' in evt['message'])
						or evt.get('slow periods')]
					ov['slowreceivers'] = f"Slow receiver disconnections = {v(len([evt for evt in slowevents if evt.get('connections delta')==-1 and 'slow' in evt['message']]))}"
					ov['slowreceivers'] += f", slow warning periods = {v(len([evt for evt in slowevents if evt.get('connections delta')==0 and evt.get('slow periods')]))}"
					if slowevents:
						# the "to" is useful for the slow periods but isn't completely accurate for the disconnections since we don't know for sure how many receivers should be connected, but better than nothing, probably
						ov['slowreceivers'] += ', '+self.formatDateTimeRange(min(e['local datetime object'] for e in slowevents), 
							max(e['local datetime object'] for e in slowevents))
						ov['slowreceivers'] += '; host(s): '+', '.join(sorted(list(set(e['connectionInfo']['host'] for e in slowevents if e.get('connectionInfo',{}).get('host')))))
					linkedfile = f"receiver_connections.{file['name']}.csv"
					if os.path.exists(self.outputdir+'/'+linkedfile):
						ov['slowreceivers'] += f" (see <a href='{linkedfile}' title='open {linkedfile} for more information; if using Chrome you may need to manually rename the downloaded file to .csv due to a browser bug'>{linkedfile}</a>)"
					
					for k in ov:
							write('  ')
							writeln(ov[k])
					writeln('</li>')

			writeln(f'</ul>Generated by Apama log analyzer v{__version__}.')


		with io.open(os.path.join(self.outputdir, 'overview.txt'), 'r', encoding='utf-8') as out:
			overviewText = out.read()
		
		log.info('Overview: \n%s%s', overviewText, '' if len(self.files)==1 else 
			'NB: Values are shown only when they differ from the preceding listed log file\n')
		self.writeOverviewHTMLForAllFiles(self.overviewHTML, **extra)

	CHARTS = { # values are (mostly) for dygraph config
		'rates':{'heading':'Send/receive rate', 'ylabel':'Events /sec', 
			'labels':['rx /sec', 'rx /sec 1min avg', 'tx /sec', 'tx /sec 1min avg'],
			'colors':['red', 'pink', 'teal', 'turquoise'], # red for received/input side; teal for transmitted/output side
			'labelsKMB':True, # for big numbers this works better than exponential notation
		}, 
		'queues':{'heading':'Correlator queues and consumers', 
			'ylabel':'Queue length', 
			'y2label':'Number of connected consumers',
			'labels':['iq=queued input', 'icq=queued input public', 'oq=queued output', 'rq=queued route', 'runq=queued ctxs', 'nc=ext+int consumers'],
			'colors':['red', 'orange', 'teal', 'purple', 'brown', 'green'],
			'series': {'nc=ext+int consumers':{'axis':'y2'}},
			'labelsKMB':True,
		},
		'logging':{'heading':'Logging', 
			'ylabel':'Lines logged /sec', 
			'y2label':'Interval between status lines (secs)',
			'series': {'interval secs':{'axis':'y2'}},
			'labels':['errors /sec', 'warns /sec', 'log lines /sec', 'interval secs'],
			'colors':['red', 'orange', 'blue', 'green'],
		}, 
		'memory':{'heading':'Correlator process memory usage', 
			'note':lambda file: f"NB: Swapping occurrences = "+(
				'?' if file.get('status-mean',{}).get('is swapping',None) is None else
				{0.0: 'none',
				}.get(file['status-mean']['is swapping'], # default value
				f"{100.0*file['status-mean']['is swapping']:.2f}% (see black dots/lines on chart)")
				+(f"; max usable memory for the correlator process (physical memory minus cgroups/licensing limits) is: <span class='overview-value'>{file['startupStanzas'][0]['usableMemoryMB']/1024.0:0.1f} GB</span>" 
				if file['startupStanzas'][0].get('usableMemoryMB') else '')),
			'y2label':'Is swapping (true=1)',
			'series': {'is swapping':{'axis':'y2'}},
			'labels':['pm=resident MB', 'jvm=Java MB', 'is swapping'],
			'colors':['red', 'blue', 'black'],
			'labelsKMG2':True, # base2 since this is memory stuff
		},
		'memoryusers':{'heading':'EPL items', 'ylabel':'Number', #'y2label':'Contexts',
			'labels':['ls=listeners', 'sm=monitor instances', 'nctx=contexts'],
			'colors':['red', 'blue', 'brown'],
			'labelsKMB':True,
			#'series':{'nctx=contexts':{'axis':'y2'}},
		},
	}
	""" # really hard to make the logscale look good due to zero values
	'swapping':{'title':'Swapping (memory pressure)', 'ylabel':'Pages swapped /sec',
		'labels':['si=swap pages read /sec', 'so=swap pages written /sec'],
		'colors':['blue', 'purple'],
		'logscale':True,
	}, 
	"""

	def getChartId(self, chartkey, file): 
		assert chartkey in self.CHARTS, chartkey
		return re.sub('[^a-zA-Z0-9_:.-]', '_', f"{chartkey}_{file['name']}") #HTML ID/NAME tokens must begin with a letter ([A-Za-z]) and may be followed by any number of letters, digits ([0-9]), hyphens ("-"), underscores ("_"), colons (":"), and periods (".").

	def writeOverviewHTMLForAllFiles(self, overviewHTML, **extra):
		title = os.path.basename(self.args.output)
		
		defaulttz = next((f['startupStanzas'][0]['utcOffset']+' (timezone is from another log file, assumed same)'
			for f in self.files if f['startupStanzas'][0].get('utcOffset')), '(unknown timezone - missing startup log file!)')
		
		defaultoptions = {
			'legend': 'always',
			'labelsSeparateLines':True,
			'highlightSeriesOpts': { 'strokeWidth': 2 },
		}

		# zoom to show everything
		times = [f.get('startTime') for f in self.files]+[f.get('endTime') for f in self.files]
		times = sorted([t for t in times if t])
		if len(times) >= 2:
			times = [min(times), max(times)]
			defaultoptions['dateWindow'] = [
				f"new Date({dt.year},{dt.month-1},{dt.day},{dt.hour},{dt.minute},{dt.second})"
				#1000*dt.timestamp()
				for dt in times
				#int(1000*min(times)), int(1000*max(times))
			]
		
		with io.open(os.path.join(self.outputdir, 'overview.html'), 'w', encoding='utf-8') as out:
			htmlstart = self.HTML_START.format(
				head=self.HTML_HEAD.replace('@title@', escapetext(title)).replace('@custom_css@', 
					'../my_log_analyzer.css' if os.path.exists(self.outputdir+'/../my_log_analyzer.css') else ''),
				title=title,
				version=__version__,
				)

			apamaversions = sorted(list(set((f['startupStanzas'][0]['apamaVersion']
				for f in self.files if f['startupStanzas'][0].get('utcOffset')))))
			if apamaversions: htmlstart = htmlstart.replace('(TODO: 5-digit Apama version here)', ', '.join(apamaversions))

			out.write(htmlstart)
			
			out.write(f"""<h3>Overview - {len(self.files)} log file{'s' if len(self.files)>1 else ''}</h3><span class="overview">{overviewHTML}</span>\n""")
			out.write('<p class="copytofrom">----- (copy up to here) -----</p>')

			out.write(f"""<h2>Charts</h2>""")

			# Table of contents - display ordered by file not chart since that's probably what we want to hide/show
			out.write('<ul class="charts_toc">\n')
			
			getid = self.getChartId
			
			for file in self.files:
				#out.write(f"<li><label><input name='Checkbox1' type='checkbox' checked>{file['index']} {file['name']}</label>\n")
				out.write(f"<li class='chartfile'>{file['index']} {escapetext(file['name'])}\n")
				if not file['showCharts']:
					out.write('<p>Not enough status lines in file to generate charts for this file; skipping.</p></li>\n')
					continue
				out.write(f" <a href='javascript:{json.dumps([getid(c,file) for c in self.CHARTS.keys()])}.forEach(c=>togglechart(c, show=false));'>(hide all)</a>")
				out.write(f" <a href='javascript:{json.dumps([getid(c,file) for c in self.CHARTS.keys()])}.forEach(c=>togglechart(c, show=true));'>(show all)</a>")
				out.write(f" <a href='javascript:{json.dumps([getid(c,file) for c in self.CHARTS.keys()])}.forEach(c=>togglechart(c, show=true));\
					{json.dumps([getid(c, f) for c in self.CHARTS.keys() for f in self.files if f !=file])}.forEach(c=>togglechart(c, show=false));'>(only)</a>")
				
				out.write(f'<ul class="charts_toc">\n')
				out.write(f"<li class='nobullet'><span class='overview-instance'>{escapetext(file['startupStanzas'][0].get('instance','<no startup stanza>'))}</span></li>")
				out.write(f"<li class='nobullet'><span class='overview-timerange'>{self.formatDateTimeRange(file['startTime'], file['endTime'], skipPrefix=True)}</span></li>\n")
				for c, info in self.CHARTS.items():
					out.write(f"<li class='nobullet'><input id='selected_{getid(c,file)}' type='checkbox' checked onclick=\"togglechart('{getid(c,file)}')\"><label><a href='#chart_{getid(c,file)}'>{escapetext(info['heading'])}</a></label></li>\n")
				out.write(f'</ul>\n')
				
			out.write('</ul>\n')

			out.write('<p>These graphs are interactive! <ul><li>To zoom in, just make a vertical or horizontal selection</li><li>To reset the zoom to show the full range of each graph, double-click</li><li>To pan, hold SHIFT while dragging.</li></ul></p>')	

			for c, info in self.CHARTS.items():
				for file in self.files:
					if not file['showCharts']: continue
					id = getid(c, file)
					tmpfile = toLongPathSafe(self.outputdir+f"/tmp/{c}_{file['name']}.json")
					if not os.path.exists(tmpfile): continue

					options = dict(info)
					
					note = options.pop('note')(file) if callable(options.get('note')) else None
					
					# remove units from label since axis contains units
					options['labels'] = ['time']+[label.split(' MB')[0] for label in options['labels']]
					
					# common defaults go here
					for k in defaultoptions: options.setdefault(k, defaultoptions[k])
					options['xlabel'] = self.formatDateTimeRange(file['startTime'], file['endTime'], skipPrefix=True)
					options['xlabel'] += ' - Local time '+(file['startupStanzas'][0].get('utcOffset',None) or defaulttz)
					
					title = options.pop('heading')
					
					instancetitle = file['startupStanzas'][0].get('instance','')
					if len(instancetitle)>40: instancetitle = instancetitle.split('[')[0] # just host:port if long

					out.write(f"""
	<div id="chartholder_{id}">
	<h4 id="chart_{id}">{escapetext(title)}: 
		<a href="#selected_{id}">{file['index']} {escapetext(file['name'])}</a>{' - ' if instancetitle else''}<code>{escapetext(instancetitle)}</code>
		<a href="javascript:togglechart('{id}');">(hide)</a>
	</h4>
	{"<p>"+note+"</p>" if note else ""}
	<div class="chartdiv chart_{c}" id="chartdiv_{id}" style="width:90%;"></div>
	</div>
	<script type="text/javascript">
		var g = new Dygraph(document.getElementById("chartdiv_{id}"), [""")
					with io.open(tmpfile, 'r', encoding='utf-8') as datafile:
						shutil.copyfileobj(datafile, out)
					os.remove(tmpfile)
					# this regex converts a JavaScript string containing new Date(...) to a proper JavaScript object
					out.write('],\n'+re.sub('"(new [^"]*)"', "\\1", json.dumps(options)[:-1])+',"legendFormatter":legendFormatter}'+'\n);\n')
					out.write('\ncharts.push(g);\n')
					if c == 'rates':
						for a in file['annotations']:
							dt = a['x']
							a['x'] = f"new Date({dt.year},{dt.month-1},{dt.day},{dt.hour},{dt.minute},{dt.second}).getTime()"
							a.update({'series':'rx /sec', 'attachAtBottom':True})
						out.write('g.setAnnotations('+re.sub('"(new [^"]*)"', "\\1", json.dumps(file['annotations'])+')'))
					out.write('</script>\n')

					
			out.write(self.HTML_END)
		if os.path.exists(os.path.join(self.outputdir, 'tmp')):
			shutil.rmtree(os.path.join(self.outputdir, 'tmp'))

	HTML_HEAD = """
	<meta charset="utf-8">
	<title>@title@ - Log Analyzer</title>

	<script src="https://cdnjs.cloudflare.com/ajax/libs/dygraph/2.1.0/dygraph.min.js"></script>
	<script src="https://cdn.jsdelivr.net/gh/danvk/dygraphs@b55a71/src/extras/synchronizer.min.js"></script>
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/dygraph/2.1.0/dygraph.min.css" />
	
	<!-- Provide a way to supply a user-defined css override that is applied to all logs generated under the current directory -->
	<link rel="stylesheet" href="@custom_css@" />

	<script type="text/javascript">
		var charts = [];
		
		var days_abbr = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
		
		function legendFormatter(data) {
			var dygraph = data.dygraph;
			var html = "";
			var showvalues = data.x != null; // false if there's no selected value currently
			
			// Need a way to lookup the JavaScript dygraph object later from the onclick listener 
			// (using just a javascript string), so assign a unique id to the div and add a data attribute to it
			// (would be great if dygraphs did this automatically)
			if (!dygraph.graphDiv.id) {
				var i = 1;
				while (document.getElementById("__dygraph"+i)) 
					i++;
				dygraph.graphDiv.id = "__dygraph"+i;
			}
			if (!dygraph.graphDiv.dygraph) { dygraph.graphDiv.dygraph = data.dygraph; }
			
			var seriesIndex = 0;
			data.series.forEach(function(series) 
			{
				html += "<label><input type='checkbox' onclick=\\"document.getElementById('"+dygraph.graphDiv.id+"').dygraph.setVisibility("+seriesIndex+", ";
				if (dygraph.visibility()[seriesIndex]) { 
					html += "false);\\" checked>";
				} else {
					html += "true);\\" >"; 
				}
				
				var labeledData = series.labelHTML;
				
				// workaround for the bug where Dygraph.prototype.setColors_ un-sets color for any series where visibility=false; 
				// this workaround gives correct color if configured using options{colors:[...]} and falls back to transparent if not
				series.dashHTML = series.dashHTML.replace("color: undefined;", "color: "+(dygraph.getColors()[seriesIndex] || "rgba(255,255,255,0.0)")+";");
				
				if (showvalues && series != undefined && series.y != undefined) { labeledData += ': ' + series.yHTML; }
				if (series.isHighlighted) { labeledData = '<b>' + labeledData + '</b>'; }
				html += series.dashHTML + " " + labeledData + "</label><br>\\n";
				seriesIndex += 1;
			});
			// Display x value at the end, after all the series (to avoid making them jump up/down when there's no selection)
			if (showvalues) {
				//console.log("Got: "+JSON.stringify(data.x));
				var thisdate = new Date(data.x);
				// data.x is a treated as a local timestamp value, and .toISOString (which we use just for formatting consistency)
				// converts to UTC, so need to add a timezone factor based on the web BROWSER's UTC offset on the specified date
				thisdate.setTime(thisdate.getTime()
					-thisdate.getTimezoneOffset()*60*1000
					);
				
				var isostring = thisdate.toISOString();
				html += days_abbr[thisdate.getDay()]+" "+isostring.slice(0, 10)+" "+isostring.slice(11, 11+8);
				var xlabel = dygraph.getOption("xlabel");
				if (xlabel.indexOf("UTC")>=0) { // add timezone if we have it in the x axis label
					html += " "+xlabel.slice(xlabel.indexOf("UTC"), xlabel.indexOf("UTC")+9);
				}
			}

			return html;
		}

	</script>

	<style>
body { font-family: tahoma; }
span.overview { }

	a { /* avoid Chrome making underlined parentheses look weird */
		text-decoration-skip-ink: none;
	}

	.dygraph-legend {
		left:80px !important;
	}
	.charts_toc > li.nobullet {
		list-style-type:none;
	}
	
	.ifyouneedhelp .key {
		font-weight:bold;
	}
	
	.overview-value, .overview-timerange, .overview-instance, .overview-swapping {
		font-weight: bold;
	}
	.overview-swapping {
		color:orange;
	}
	.overview-warning {
		color:orange;
	}
	.overview-instance {
	  /*font-family: monospace;*/
	}
	
	.copytofrom {
		font-style: italic;
	}
	</style>
"""
	HTML_START = """<!DOCTYPE html>
<!-- saved from url=(0052)https://github.com/ApamaCommunity/apama-log-analyzer -->
<html>
<head>
{head}
</head>
<body>
<h1>{title} - Analyzer HTML Overview</h1>
<p>Generated by Log Analyzer {version}. <a href="." title="NB: local links don't work in IE; use another browser or copy link to clipboard">Click here</a> to see all generated files. For more information about the latest version of the analyzer <a href='https://github.com/ApamaCommunity/apama-log-analyzer'>see here</a>.</p>

<h2>If you need help</h2>
<p>If you need help analyzing a log file, here's the essential information you need to include (along with attachment/links to the original correlator logs!): </p>
<p class="copytofrom">----- (copy from here) -----</p>
<ol class="ifyouneedhelp">
<li><span class="key">Apama version: </span>(TODO: 5-digit Apama version here)</li>
<li><span class="key">Date/time(s) when problem occurred: </span>(TODO: START to END; include date, time, and TIMEZONE)</li>
<li><span class="key">Original correlator logs: </span>(TODO: Links/attachment containing original correlator log files - must cover both the time when the problem occurred AND also the time the correlator was started, as the startup messages contain vital information)</li>
<li><span class="key">Nature of the problem: </span>(TODO: e.g. reduced latency or throughput performance, out of memory, correlator terminated unexpectedly, logic error or ERROR logged by EPL monitor, confusing log message, etc; put the problem type and customer name into the subject line)</li>
<li><span class="key">Reproducibility: </span>(TODO: How many times has the problem occurred and how frequently? Can it be reproduced in a test environment?)</li>
<li><span class="key">Application experts: </span>(TODO: What contacts/departments within Software AG and/or customer knows the codebase of the EPL application?)</li>
<li><span class="key">Log analyzer overview: </span>(see overview below)</li>
</ol></p>
"""

	HTML_END = """
	<script type="text/javascript">
		var chartsSync = Dygraph.synchronize(charts, {
			selection: true,
			zoom: true,
			range: false,
		});

		function togglechart(id, show=null) // null means toggle 
		{
			if (show===true || (show===null && document.getElementById("chartholder_"+id).style.display === "none")) {
				document.getElementById("chartholder_"+id).style.display = "block";
				document.getElementById("selected_"+id).checked = true;
			} else {
				document.getElementById("chartholder_"+id).style.display = "none";
				document.getElementById("selected_"+id).checked = false;
			}
		}

	</script>
	</body></html>"""

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
		x = os.path.basename(filename)
		for r in ['.output.log', '.log', '.logs']:
			if x.endswith(r): x = x[:-len(r)]
		return x
	

class LogAnalyzerTool(object):
	"""
	Class for the command line tool. Subclass this if you wish to add extra 
	arguments to the parser. 
	
	@ivar argparser: A argparse.ArgumentParser that subclasses can add arguments to if desired. 
	"""
	def __init__(self, analyzerFactory=LogAnalyzer):
		self.analyzerFactory = analyzerFactory

		self.argparser = argparse.ArgumentParser(description=u'Analyzes Apama correlator log files v%s'%(__version__), 
			epilog=u'For Apama versions before 10.3 only the first log file contains the header section specifying version and environment information, so be sure to include that first log file otherwise critical information will be missing.')
			
		self.argparser.add_argument('--loglevel', '-l', '-v', default='INFO',
			help='Log level/verbosity for this tool')
		self.argparser.add_argument('files', metavar='FILE', nargs='+',
			help='One or more correlator log files to be analyzed; directories and glob-style expressions such as *.log are permitted. Archives such as .zip/.tar.gz/.xz will be automatically extracted.')
		self.argparser.add_argument('--output', '-o', metavar='DIR',  # later might also support zip output
			help='The directory to which output files will be written. Existing files are overwritten if it already exists.')
		self.argparser.add_argument('--autoOpen', action='store_true',
			help='Automatically open overview.html in a web browser on completion. Can also be enabled with the environment variable APAMA_ANALYZER_AUTO_OPEN=true')

		self.argparser.add_argument('--skip', metavar='N%', type=str, 
			help='Skips the first N%% of the file (in bytes) to ignore startup noise and focus on the period of interest which is usually near the end; note that the startup stanza is still read from the beginning of the file if present.')

		self.argparser.add_argument('--json', action='store_true',
			help='Advanced/debugging option to additionally write output in JSON format suitable for processing by scripts.')

		self.argparser.add_argument('--config', metavar="FILE.json", type=str,
			help='Configure the analyzer for advanced functionality such as custom/user-supplied log line extraction.')

		self.argparser.add_argument('--XmaxUniqueWarnOrErrorLines', metavar='INT', default=1000, type=int,
			help='Advanced option to put an upper limit on the number of unique warn/error log lines that will be held in memory. Specify 0 to disable warn/error line tracking.')
		self.argparser.add_argument('--XmaxSampleWarnOrErrorLines', metavar='INT', default=5, type=int,
			help='Advanced option to specify how many sample warn/error log lines to include in the summary for each unique log message. Use 0 to include all matching log lines.')
		
		
	def main(self, args):
		args = self.argparser.parse_args(args)
		if args.skip: 
			args.skip=float(args.skip.strip('% '))
		loglevel = getattr(logging, args.loglevel.upper())
		logging.basicConfig(format=u'%(relativeCreated)05d %(levelname)-5s - %(message)s' if loglevel == logging.DEBUG 
			else u'%(levelname)-5s - %(message)s', 
			stream=sys.stderr, level=loglevel)

		log.info('Apama log analyzer v%s (locale=%s)'%(__version__, locale.getdefaultlocale()[0]))
		
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

		userCharts = {}
		if args.config:
			with open(args.config, 'rb') as f:
				jsonbytes = f.read()
				# permit # and // comments in the JSON file for added usability
				jsonbytes = re.sub(b'^[\t ]*(#|//).*', b'', jsonbytes, flags=re.MULTILINE)
				for k, v in json.loads(jsonbytes).items():
					if k == 'userStatusLines':
						args.userStatusLines = v
						# sanity check it
						columns = {k or COLUMN_DISPLAY_NAMES[k] for k in COLUMN_DISPLAY_NAMES}
						for userStatusPrefix, userStatus in v.items():
							for k, alias in userStatus['key:alias'].items():
								alias = userStatus['keyPrefix']+(alias or k)
								if alias in columns: raise UserError(f"User status line '{userStatusPrefix}' contains display name '{alias}' which is already in use; consider using keyPrefix to ensure this status line doesn't conflict with display names from others")
								columns.add(alias)
						
						# need a hack to cope with [n] placeholders for monitor instance id
						args.userStatusLines = {
							(k[:k.index('[')+1] if ('[' in k and ']' in k) else k, # simple and hence efficient prefix match
							k[k.index(']'):] if ('[' in k and ']' in k) else None,
							):v for k, v in args.userStatusLines.items()
						}
						
					elif k == 'userCharts':
						userCharts = v # allow overriding existing charts if desired
					else:
						raise UserError('Unknown key in config file: '%key)
		else:
			args.userStatusLines = {}
		
		if not globbedpaths: raise UserError('No log files specified')
		
		if not args.output: 
			# if not explicitly specified, create a new unique dir
			outputname = 'log_analyzer_%s'%LogAnalyzer.logFileToLogName(globbedpaths[-1]) # base it on the most recent name
			# make sure we strip off any .zip or similar extension (but not numeric suffixes which could be part of a date/time)
			outputname = re.sub('[.]..?[a-zA-Z]$', '', outputname)
			args.output = toLongPathSafe(outputname)
			i = 2
			while os.path.exists(args.output) and os.listdir(args.output): # unless it's empty
				args.output = toLongPathSafe('%s_%02d'%(outputname, i))
				i += 1
		args.output = toLongPathSafe(args.output)
		args.outputUserFriendly = args.output[4:] if args.output.startswith('\\\\?\\') else args.output

		log.info('Output directory is: %s', args.outputUserFriendly)
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
				if 'overview.txt' in filenames:
					raise UserError(f'Log analyzer cannot be used to analyze an output directory generated by itself ({dirpath}). Instead, please run the analyzer on the original log files.')
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
		manager.CHARTS.update(userCharts) # allow overriding existing charts if desired

		manager.processFiles(sorted(list(logpaths)))

		duration = time.time()-duration
		log.info('Completed analysis in %s', (('%d seconds'%duration) if duration < 120 else ('%0.1f minutes' % (duration/60))))
		if args.autoOpen or os.getenv('APAMA_ANALYZER_AUTO_OPEN')=='true':
			log.info(f'Automatically opening {os.path.normpath(args.outputUserFriendly+"/overview.html")}')
			os.system('"'+os.path.normpath(args.outputUserFriendly+"/overview.html")+'"')
		else:
			log.info(f'Output is in {args.outputUserFriendly} (overview.html is a good starting place)')

		log.info('')
		log.info('If you need to request help analyzing a log file be sure to tell us: the 5-digit Apama version, the time period when the bad behaviour was observed, any ERROR/WARN messages, and attach the full original correlator log files (including the very first log file - which contains all the header information - and also the log files during the times when the bad behaviour occurred). ')
		
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
orig_exists = os.path.exists
os.path.exists = lambda path: orig_exists(toLongPathSafe(path))

if __name__ == "__main__":
	try:
		sys.exit(LogAnalyzerTool().main(sys.argv[1:]))
	except UserError as ex:
		sys.stderr.write(f'ERROR - {ex}\n')
		sys.exit(100)
