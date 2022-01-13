import io
import datetime
import json
import math
import calendar
import time
import pysys
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
			self.write_text('user_status_final.txt', '\n'.join(['%s=%r'%(k, final[k]) for k in header if not k.startswith('ctrlIncomingNode')]))
			
		self.logFileContents('user_status_final.txt', maxLines=0)
		self.assertDiff('user_status_final.txt')
		
		status = pysys.utils.fileutils.loadJSON(self.output+'/loganalyzer_output/status.correlator.json')['status']
		self.write_text('apamactrlProxyStatus.txt', 
			'\n\n'.join(
				line['local datetime']+'\n'+
				'\n'.join(f'{k}={v}' for k,v in line.items() if k.split('.')[0] in ['ctrlIncomingNode1', 'ctrlIncomingNode2', 'ctrlIncomingNode3', 'ctrlIncomingNode4'] )
				for line in status[1:] # ignore first correlator status line where we didn't have any apama-ctrl status
			))
		self.logFileContents('apamactrlProxyStatus.txt', maxLines=0)
