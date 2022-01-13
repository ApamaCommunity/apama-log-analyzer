__pysys_title__   = r""" Status lines - apama-ctrl CepServlet Proxy Status""" 
#                        ================================================================================

__pysys_purpose__ = r""" 
	""" 
	
__pysys_authors__ = "bsp"
__pysys_created__ = "2022-01-13"

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
			], logfiles=[
			self.input+'/correlator.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		header = self.getExprFromFile('loganalyzer_output/status.correlator.csv', '# (.*)').strip().split(',')
			
		status = pysys.utils.fileutils.loadJSON(self.output+'/loganalyzer_output/status.correlator.json')['status']
		self.write_text('apamactrlProxyStatus.txt', 
			'\n\n'.join(
				line['local datetime']+'\n'+
				'\n'.join(f'{k}={v if not k.endswith("/sec") else ("None" if v is None else v)}' for k,v in line.items() if k.split('.')[0] in 
					['ctrlIncomingNode1', 'ctrlIncomingNode2', 'ctrlIncomingNode3', 'ctrlIncomingNode4'] )
				for line in status
			))
		self.logFileContents('apamactrlProxyStatus.txt', maxLines=0)
		
		self.assertDiff('apamactrlProxyStatus.txt')
