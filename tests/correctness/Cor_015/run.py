import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):			
		self.logAnalyzer(['--json'], logfiles=[
			'correlator.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		rconn = 'loganalyzer_output/receiver_connections.correlator.csv'
		self.logFileContents(rconn, maxLines=0)
		
		# basic check: ensure all connections have been registered
		self.assertLineCount(rconn, expr=',Receiver connected', condition='==8')
		
		self.assertDiff(rconn, 'receiver_connections.correlator.csv', replace=[
			# ignore metadata contents, that's not what we're testing here
			('# metadata: .*', '# metadata: XXX'),
			])
			
		self.assertGrep('loganalyzer_output/overview.txt', expr='Slow receiver disconnections = 2, slow warning periods = 3, from Tue 2019-11-12 17:09:20 to 17:40:00 (=0:30:39); host(s): 127.0.0.1, 192.10.9.8 (see receiver_connections.correlator.csv)', literal=True)
		