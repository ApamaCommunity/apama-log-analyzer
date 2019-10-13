import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):			
		self.logAnalyzer(['--XmaxSampleWarnOrErrorLines', '0',
			], logfiles=[
			'*.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		
		self.logFileContents('loganalyzer_output/logged_errors.txt', maxLines=0)
		self.logFileContents('loganalyzer_output/logged_warnings.txt', maxLines=0)
		
		self.assertDiff('loganalyzer_output/logged_errors.txt', 'ref-errors.txt')
		self.assertDiff('loganalyzer_output/logged_warnings.txt', 'ref-warnings.txt')