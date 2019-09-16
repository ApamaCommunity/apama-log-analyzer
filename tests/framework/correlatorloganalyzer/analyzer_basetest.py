import os, sys, collections
from pysys.constants import *
from pysys.basetest import BaseTest

class AnalyzerBaseTest(BaseTest):
	def __init__(self, *args, **kwargs):
		super(AnalyzerBaseTest, self).__init__(*args, **kwargs)
		if 'performance' in self.descriptor.groups:
			self.disableCoverage=True

	def logAnalyzer(self, arguments, logfiles=None, output='<testdefault>', stdouterr='loganalyzer', logstderr=True, **kwargs):
		"""
		Run log analyzer. 
		
		@param logfiles: a list of log files
		@param output: set to None to let tool pick a default. Else test puts it into 'loganalyzer_output'
		"""
		if output == '<testdefault>':
			output = stdouterr+'_output'
		try:
			args = [self.project.logAnalyzerScript]+arguments
			if logfiles:
				args = args+[os.path.join(self.input, l) for l in logfiles]
			if output:
				args = args+['--output', output]
				
			return self.startPython(
				arguments=args,
				stdouterr=stdouterr, 
				**kwargs
			)
		finally:
			if output and os.path.exists(os.path.join(self.output, output)):
				self.log.info('   Generated output files: %s', sorted(os.listdir(os.path.join(self.output, output))))
			if logstderr: self.logFileContents(stdouterr+'.err')

	def checkForAnalyzerErrors(self, stdouterr='loganalyzer'):
		self.assertGrep(stdouterr+'.err', expr='(ERROR |Traceback).*', contains=False)
	
