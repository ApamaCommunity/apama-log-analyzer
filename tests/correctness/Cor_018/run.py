import io
import datetime
import json
import math
import calendar
import time
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):

	def execute(self):
		self.logAnalyzer(['--json', 
				'--config', self.input+'/analyzer_config.json'
			], logfiles=[
			self.input+'/correlator.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		header = self.getExprFromFile('loganalyzer_output/status.correlator.csv', '# (.*)').strip().split(',')
		header = header[header.index('myApp.kpi1'):header.index('# metadata: ')]
		with open(self.output+'/loganalyzer_output/summary_status.correlator.json', 'rb') as f:
			summary = json.load(f)['status']
			final = [x for x in summary if x['statistic']=='100% (end)'][0]
			self.write_text('user_status_final.txt', '\n'.join(['%s=%r'%(k, final[k]) for k in header]))
			
		self.logFileContents('user_status_final.txt', maxLines=0)
		self.assertDiff('user_status_final.txt')
