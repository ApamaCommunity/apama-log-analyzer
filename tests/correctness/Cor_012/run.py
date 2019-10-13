import json, io, re
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer([
			# these are mostly just here for manual testing purposes and to show there's no error
			self.input+'/correlator-4.3.2.0-win.log', 
			self.input+'/correlator-10.3.1.0-win.log', 
			# hacked up to have everything turned on
			self.input+'/correlator-10.5.1.0-linux-everything.log', 
			'--json'
		])


	def validate(self):
		self.checkForAnalyzerErrors()
		outputdir = self.output+'/loganalyzer_output'
		self.assertDiff(outputdir+'/startup_summary_correlator-10.5.1.0-linux-everything.json', 
			'ref_startup_summary_correlator-everything.json', replace=[
				('"analyzerVersion": *".+"', '"analyzerVersion":"VERSIONHERE"'),
		])
		
		self.copy(outputdir+'/status_correlator-10.5.1.0-linux-everything.csv', 'csv-metadata.txt', mappers=[
			lambda line: None if ('# metadata: ' not in line) else re.sub('\n([0-9])',',\\1', line[line.find('# metadata'):].replace(',','\n').replace('=\n','=')), 
		])
		self.logFileContents('csv-metadata.txt')
		self.assertDiff('csv-metadata.txt', 'ref-csv-metadata.txt', replace=[
			('analyzerVersion=.+', 'analyzerVersion=VERSIONHERE'),
		])
		
		self.assertGrep(outputdir+'/startup_stanza_correlator-10.5.1.0-linux-everything.log', 
			expr='Correlator, version .*started')
		self.assertGrep(outputdir+'/startup_stanza_correlator-10.5.1.0-linux-everything.log', 
			expr='Correlator, version .*running')
		self.assertGrep(outputdir+'/startup_stanza_correlator-10.5.1.0-linux-everything.log', 
			expr='INFO ')
		self.assertGrep(outputdir+'/startup_stanza_correlator-10.5.1.0-linux-everything.log', 
			expr='Shutting down correlator', contains=False) # #### level message not part of startup
