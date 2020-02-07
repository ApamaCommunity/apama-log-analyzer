import json, io, re
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.copy(self.input+'/correlator-10.5.1.0-linux-everything.log', 'x-copy-of-correlator-10.5.1.0-linux-everything.log')
		self.logAnalyzer([
			# deliberately add a copy with a different name and order, to check for sorting in the overview
			self.output+'/x-copy-of-correlator-10.5.1.0-linux-everything.log',
			
			# these are mostly just here for manual testing purposes and to show there's no error
			self.input+'/correlator-4.3.2.0-win.log', 
			self.input+'/correlator-10.3.1.0-win.log', 
			# hacked up to have everything turned on
			self.input+'/correlator-10.5.1.0-linux-everything.log', 
			
			self.input+'/correlator-with-restarts.log',
			self.input+'/correlator-without-startup.log',
			'--json'
		])


	def validate(self):
		self.checkForAnalyzerErrors()
		outputdir = self.output+'/loganalyzer_output'
		self.assertDiff(outputdir+'/startup_stanza.correlator-10.5.1.0-linux-everything.json', 
			'ref_startup_summary_correlator-everything.json', replace=[
				('"analyzerVersion": *".+"', '"analyzerVersion":"VERSIONHERE"'),
		])
		
		self.copy(outputdir+'/status.correlator-10.5.1.0-linux-everything.csv', 'csv-metadata.txt', mappers=[
			lambda line: None if ('# metadata: ' not in line) else re.sub('\n([0-9])',',\\1', line[line.find('# metadata'):].replace(',','\n').replace('=\n','=')), 
		])
		self.logFileContents('csv-metadata.txt')
		self.assertDiff('csv-metadata.txt', 'ref-csv-metadata.txt', replace=[
			('analyzerVersion=.+', 'analyzerVersion=VERSIONHERE'),
		])
		
		self.assertGrep(outputdir+'/startup_stanza.correlator-10.5.1.0-linux-everything.log', 
			expr='Correlator, version .*started')
		self.assertGrep(outputdir+'/startup_stanza.correlator-10.5.1.0-linux-everything.log', 
			expr='Correlator, version .*running')
		self.assertGrep(outputdir+'/startup_stanza.correlator-10.5.1.0-linux-everything.log', 
			expr='INFO ')
		self.assertGrep(outputdir+'/startup_stanza.correlator-10.5.1.0-linux-everything.log', 
			expr='Shutting down correlator', contains=False) # #### level message not part of startup

		# check for negative rates after restarts
		with io.open(self.output+'/loganalyzer_output/status.correlator-with-restarts.json') as f:
			s = json.load(f)['status']
			for statusline in s:
				for k in ['interval secs', 'rx /sec', 'tx /sec', 'log lines /sec']:
					self.assertEval('{val} >= 0', val=statusline[k], key=k)

		# strip out the stats since we test them elsewhere
		self.copy(outputdir+'/overview.txt', 'overview-without-stats.txt', mappers=[
			lambda line: None if ' = ' in line else line])

		self.assertDiff('overview-without-stats.txt', 'ref-overview.txt', replace=[
			('Apama log analyzer v[0-9].+/.+', 'Apama log analyzer vXXX')])

		self.logFileContents(outputdir+'/overview.txt', maxLines=0)
