import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer(['--json'], logfiles=['correlator1.log', 'correlator2.log'])

	def validate(self):
		self.checkForAnalyzerErrors()
		
		# ensure correct order
		self.assertOrderedGrep('loganalyzer.err', exprList=[
			'Starting analysis of correlator1.log',
			'Starting analysis of correlator2.log',
		])
		

		outputdir = self.output+'/loganalyzer_output'

		# logs look sane, contains the right timestamps
		self.assertGrep(outputdir+'/status_correlator1.json', expr='2019-04-08 ')
		self.assertGrep(outputdir+'/status_correlator2.json', expr='2019-04-09 ')

		# ensure log 2 not affected by values from log 1
		self.assertGrep(outputdir+'/status_correlator2.json', expr='2019-04-09 13:57:32.*"rx /sec": 0,')
		# but is affected by its own prev values
		self.assertGrep(outputdir+'/status_correlator2.json', expr='2019-04-09 13:57:33.*"rx /sec": 100.0,')

		with io.open(outputdir+'/status_correlator1.json') as f:
			json.load(f) # check it's a valid json document
		with io.open(outputdir+'/status_correlator2.json') as f:
			json.load(f) # check it's a valid json document
