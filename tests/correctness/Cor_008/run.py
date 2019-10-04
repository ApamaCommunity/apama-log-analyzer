import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):			
		self.logAnalyzer(['--statusjson'], logfiles=[
			'correlator-warns-and-errors.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()

		log='warns-and-errors'
		with io.open(self.output+f'/loganalyzer_output/status_correlator-{log}.json') as f:
			s = json.load(f)['status']

		# first line will have zeros since can't calculate a rate withut a line period
		line = 0
		self.assertEval("{value} == 0", value=s[line]['warns'], valueName=f'warns for {log}.log line {line}')
		self.assertEval("{value} == 0", value=s[line]['errors'], valueName=f'errors for {log}.log line {line}')
		self.assertEval("{value} == 0", value=s[line]['log lines /sec'], valueName=f'total log lines for {log}.log line {line}')

		# second line also includes warns from before the first line
		line = 1
		self.assertEval("{value} == 2", value=s[line]['warns'], valueName=f'warns for {log}.log line {line}')
		self.assertEval("{value} == 3", value=s[line]['errors'], valueName=f'errors for {log}.log line {line}')
		self.assertEval("{value} == 7/5.0", value=s[line]['log lines /sec'], valueName=f'total log lines for {log}.log line {line}')

		line = 2
		self.assertEval("{value} == 0", value=s[line]['warns'], valueName=f'warns for {log}.log line {line}')
		self.assertEval("{value} == 1", value=s[line]['errors'], valueName=f'errors for {log}.log line {line}')
