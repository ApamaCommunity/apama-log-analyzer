import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):	
		self.logAnalyzer(['--XmaxSampleWarnOrErrorLines', '0',
			], logfiles=['correlator1.log','correlator2.log'], stdouterr='loganalyzer-unlimited')

		self.logAnalyzer(['--XmaxSampleWarnOrErrorLines', '7',
			], logfiles=['correlator1.log','correlator2.log'], stdouterr='loganalyzer-limited-7')
		self.logAnalyzer(['--XmaxSampleWarnOrErrorLines', '4',
			], logfiles=['correlator1.log','correlator2.log'], stdouterr='loganalyzer-limited-4')

		self.logAnalyzer(['--XmaxUniqueWarnOrErrorLines', '3',
			], logfiles=['correlator1.log','correlator2.log'], stdouterr='loganalyzer-XmaxUniqueWarnOrErrorLines-3')

	def validate(self):
		self.checkForAnalyzerErrors(stdouterr='loganalyzer-limited-7')

		self.assertGrep('loganalyzer-unlimited_output/warnings.txt', expr='This is a #1 unique warning message')
		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='This is a #1 unique warning message')

		self.assertLineCount('loganalyzer-unlimited_output/warnings.txt', expr='ABC warning for process [0-9]', condition='==14+2')
		self.assertLineCount('loganalyzer-unlimited_output/warnings.txt', expr='ODD warning for process [0-9]', condition='==15+2')

		# 7 limit is hit for the first log file, but we allow a single extra one for later log files
		self.assertLineCount('loganalyzer-limited-7_output/warnings.txt', expr='ABC warning for process [0-9]', condition='==7+1')
		self.assertLineCount('loganalyzer-limited-7_output/warnings.txt', expr='ODD warning for process [0-9]', condition='==7')

		# 4+1 because of remainder after dividing an odd number into two
		self.assertLineCount('loganalyzer-limited-4_output/warnings.txt', expr='warning for process [0-9]', condition='<= (4+1)*2*2')

		# check we sample from the start and end
		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='2019-01-01 .*ABC warning for process 1 ')
		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='2019-01-01 .*ABC warning for process 14 ')
		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='2019-02-02 .*ABC warning for process 01 ')

		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='ODD warning for process 01 ')
		self.assertGrep('loganalyzer-limited-7_output/warnings.txt', expr='ODD warning for process 015 ')
		
		# check limit on number of unique messages
		self.assertLineCount('loganalyzer-XmaxUniqueWarnOrErrorLines-3_output/warnings.txt', expr='--- ', condition='==3')
		self.assertGrep('loganalyzer-XmaxUniqueWarnOrErrorLines-3_output/warnings.txt', expr='WARNING: .*XmaxUniqueWarnOrErrorLines')
