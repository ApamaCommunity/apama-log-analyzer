import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer([
			self.input+'/apama-ctrl-10.5.0.0.log', 
			self.input+'/apama-small-10.3.1.0.log', 
			self.input+'/apama-ctrl-10.5.0.2.log', 
			'--json', 
		])


	def validate(self):
		self.checkForAnalyzerErrors()
		outputdir = self.output+'/loganalyzer_output'

		logversion = '10.5.0.0'
		with io.open(outputdir+f'/status.apama-ctrl-{logversion}.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		self.assertEval("{value}.startswith('2019-09-16 ')", value=last['local datetime'], valueName=f'last datetime for {logversion}')
		self.assertEval("{value} == 12345", value=last['sm=monitor instances'], valueName=f'last sm value for {logversion} log')

		logversion = '10.3.1.0'
		with io.open(outputdir+f'/status.apama-small-{logversion}.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		self.assertEval("{value}.startswith('2019-09-24 ')", value=last['local datetime'], valueName=f'last datetime for {logversion}')
		self.assertEval("{value} == 12345", value=last['sm=monitor instances'], valueName=f'last sm value for {logversion} log')

		self.assertGrep(outputdir+'/logged_warnings.txt', expr=r'767 .*2019-09-16 10:27:41.499 WARN  \[Thread-8\] com.apama.in_c8y.AlarmUtil.raise - MAJOR APAMA_CTRL_ERROR_63951550 CalculatePowerValues')
		# 2x occurrences of this message
		self.assertGrep(outputdir+'/logged_errors.txt', expr=r'2.* eplfiles.CalculatePowerValues.CalculatePowerValues')
		
		# check overview includes apama-ctrl
		self.assertGrep(outputdir+'/overview.txt', expr='Apama version: +10.5.0.0.357983, apama-ctrl: 10.5.0.1_359159M; ')
		self.assertGrep(outputdir+'/overview.txt', expr='Apama version: +10.5.0.1.[0-9]+, apama-ctrl: 10.5.0.2_[0-9]+; ')

		self.assertGrep(outputdir+'/status.apama-ctrl-10.5.0.0.csv', expr='apamaCtrlVersion=,10.5.0.1_359159M')

		
		self.logFileContents(outputdir+'/overview.txt', maxLines=0)