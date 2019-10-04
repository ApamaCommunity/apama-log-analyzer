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
		
		self.logFileContents('loganalyzer_output/errors.txt', maxLines=0)
		self.logFileContents('loganalyzer_output/warnings.txt', maxLines=0)
		
		self.assertDiff('loganalyzer_output/errors.txt', 'ref-errors.txt')
		self.assertDiff('loganalyzer_output/warnings.txt', 'ref-warnings.txt')