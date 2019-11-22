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
