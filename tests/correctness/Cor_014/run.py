import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		# test globbing, handling of directories and archives
		self.logAnalyzer([], logfiles=[self.input+'/mydir', self.input+'/archive*'])
		
		self.write_text('valid-log-files.txt', '\n'.join(f for f in os.listdir(self.output+'/loganalyzer_output') if f.startswith('startup_stanza.')), encoding='utf-8')

	def validate(self):
		self.checkForAnalyzerErrors()
		self.logFileContents('loganalyzer.err', maxLines=0)
		self.logFileContents('valid-log-files.txt', maxLines=0)
		
		self.assertDiff('valid-log-files.txt', 'ref-valid-log-files.txt')
		