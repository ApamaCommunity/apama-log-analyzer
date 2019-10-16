import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer(['--json'], logfiles=['no-swapping.log'], stdouterr='no-swapping')
		self.logAnalyzer(['--json'], logfiles=['swapping-period.log'], stdouterr='swapping-period')
		self.logAnalyzer(['--json'], logfiles=['swapping-to-end.log'], stdouterr='swapping-to-end')

	def validate(self):
		self.checkForAnalyzerErrors('no-swapping')
		self.checkForAnalyzerErrors('swapping-period')
		self.checkForAnalyzerErrors('swapping-to-end')
		self.copy('no-swapping_output/overview.txt', 'overview-stats-no-swapping.txt', mappers=[
			lambda line: line if ' = ' in line else None,
		])

		# diff the no-swapping log
		self.assertDiff('no-swapping_output/overview.txt', 'ref-no-swapping-overview.txt')
		
		self.logFileContents('overview-stats-no-swapping.txt', maxLines=0)

		# just check a few details in the other ones
		
		# this is where we test the max value logic still works if max is from the first status (it's a special case)
		self.assertGrep('swapping-period_output/overview.txt', expr='resident memory max.* 29.087 GB.*, at Tue 2019-04-09 13:57:30 .*line 77')
		self.assertGrep('swapping-period_output/overview.txt', expr='Swapping occurrences = 33.33% of log file, from Tue 2019-04-09 13:57:40 to 13:58:10 (=0:00:30), beginning at line 80', literal=True)
		self.assertGrep('swapping-period_output/overview.txt', expr='Queued input max = 19,000 at Tue 2019-04-09 13:57:30 (line 77)', literal=True)

		self.assertGrep('swapping-to-end_output/overview.txt', expr='Queued input max = 19,000 at Tue 2019-04-09 13:57:30 (line 77)', literal=True)
