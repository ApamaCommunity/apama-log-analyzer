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
		self.assertLineCount(rconn, expr=',External receiver connected from', condition='==4')
		
		self.assertDiff(rconn, 'receiver_connections.correlator.csv', replace=[
			# ignore metadata contents, that's not what we're testing here
			('# metadata: .*', '# metadata: XXX'),
			])
			
		self.assertGrep('loganalyzer_output/overview.txt', expr='Slow receiver disconnections = 1, slow warning periods = 3', literal=True)
