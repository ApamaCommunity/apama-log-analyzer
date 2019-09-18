import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer([
			self.input+'/apama-ctrl-10.5.0.0.log', 
			self.input+'/apama-small-10.3.1.0.log', 
			'--statusjson', 
		])


	def validate(self):
		self.checkForAnalyzerErrors()
		outputdir = self.output+'/loganalyzer_output'

		logversion = '10.5.0.0'
		with io.open(outputdir+f'/status_apama-ctrl-{logversion}.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		self.assertEval("{value}.startswith('2019-09-16 ')", value=last['datetime'], valueName=f'last datetime for {logversion}')
		self.assertEval("{value} == 12345", value=last['sm=monitor instances'], valueName=f'last sm value for {logversion} log')

		logversion = '10.3.1.0'
		with io.open(outputdir+f'/status_apama-small-{logversion}.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		self.assertEval("{value}.startswith('2019-09-24 ')", value=last['datetime'], valueName=f'last datetime for {logversion}')
		self.assertEval("{value} == 12345", value=last['sm=monitor instances'], valueName=f'last sm value for {logversion} log')
