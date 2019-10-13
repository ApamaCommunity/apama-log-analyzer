import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer(['--json'], logfiles=['empty.log', 'garbage.log'])

	def validate(self):
		self.checkForAnalyzerErrors()
		
		# ensure correct order
		self.assertGrep('loganalyzer.err', expr='Starting analysis of empty.log')
		self.assertGrep('loganalyzer.err', expr='Starting analysis of garbage.log')
		self.assertGrep('loganalyzer.err', expr='WARN.* 0 status line[(]s[)] found in empty; not enough to analyze')
		self.assertGrep('loganalyzer.err', expr='WARN.* 0 status line[(]s[)] found in garbage; not enough to analyze')

		outputdir = self.output+'/loganalyzer_output'
		self.assertEval('{output_files}==["overview.txt"]', output_files=os.listdir(outputdir))
