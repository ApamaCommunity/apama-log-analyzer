import io
import datetime
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest
from pysys.utils.perfreporter import PerformanceUnit

class PySysTest(AnalyzerBaseTest):
	durationSecs = 3.0
	
	def execute(self):
		self.logAnalyzer(arguments=[
				str(self.durationSecs),
				self.mode,
			], 
			script=self.input+'/perf.py',
			stdouterr='perf', 
			environs=self.createEnvirons(
				{'PYTHONPATH':os.path.dirname(self.project.logAnalyzerScript)+'/..'},
				command=sys.executable, 
			))
		

	def validate(self):
		self.checkForAnalyzerErrors(stdouterr='perf')
		
		if 'Status' in self.mode:
			# this statistic is only meaningful when we are doing periodic status lines
			rate = float(self.getExprFromFile('perf.err', 'Completed performance test:.* ([0-9.]+) log hours per second'))
			self.reportPerformanceResult(rate, 
				'Processing rate for each hour of %s log messages' % self.mode, 
				unit=PerformanceUnit('log hours/s', biggerIsBetter=True),
				resultDetails=[('mode',self.mode)])
		
		rate = float(self.getExprFromFile('perf.err', 'Completed performance test:.* ([0-9.]+) total lines/second'))
		self.reportPerformanceResult(rate, 
			'Processing rate for %s log messages' % self.mode, 
			unit=PerformanceUnit('lines/s', biggerIsBetter=True),
			resultDetails=[('mode',self.mode)])
