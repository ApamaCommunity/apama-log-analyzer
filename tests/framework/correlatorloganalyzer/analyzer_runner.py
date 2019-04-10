import os, sys, collections
from pysys.constants import *
from pysys.baserunner import BaseRunner

class AnalyzerRunner(BaseRunner):
	def setup(self, **kwargs):
		super(AnalyzerRunner, self).setup(**kwargs)
		if getattr(self, 'PYTHON_COVERAGE','')=='true':
			self.pythonCoverageDir = self.project.testRootDir+'/pysys-output-coverage'
			self.log.info('Python coverage enabled - writing to: %s', self.pythonCoverageDir)
			self.deletedir(self.pythonCoverageDir)
			self.mkdir(self.pythonCoverageDir)
			self.pythonCoverageIndex = 0
		else:
			self.pythonCoverageDir = None
		
	def testComplete(self, testObj, dir, **kwargs):
		if self.pythonCoverageDir:
			for f in os.listdir(dir):
				if f.startswith('.coverage'):
					self.pythonCoverageIndex += 1
					os.rename(dir+'/'+f, self.pythonCoverageDir+'/%s_%03d'%(f, self.pythonCoverageIndex))
		super(AnalyzerRunner, self).testComplete(testObj, dir, **kwargs)


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
			return self.startProcess(sys.executable, 
				arguments=args,
				stdouterr=stdouterr, 
				**kwargs
			)
		finally:
			if output and os.path.exists(os.path.join(self.output, output)):
				self.log.info('   Generated output files: %s', sorted(os.listdir(os.path.join(self.output, output))))
			if logstderr: self.logFileContents(stdouterr+'.err')

	def checkForAnalyzerErrors(self, stdouterr='loganalyzer'):
		self.assertGrep(stdouterr+'.err', expr='(ERROR.*|Traceback.*)', contains=False)
	
	def assertEval(self, evalstring, abortOnError=False, **params):
		"""Perform a validation based on a python eval string.

		The eval string should be specified as a format string, with zero or more %s-style
		arguments. This provides an easy way to check conditions that also produces clear
		outcome messages.
		
		String arguments are automatically passed through repr. 

		e.g. 
		self.assertThat('os.path.size({filename}) > {origFileSize}',      
			filename=self.output+'/file.txt', origFileSize=1000) 
		
		@param evalstring: A string will have any following args 
		substituted into it and then be evaluated as a boolean python 
		expression. 
		
		@param args: Keyword arguments for each item to be passed to the condition 
		string. If a value is a callable it will be executed. All values are 
		then passed through repr(). 
		
		@keyword abortOnError: Set to True to make the test immediately abort if the
		assertion fails. 
		"""
		formatargs = collections.OrderedDict() # python 3 maintains order of kwargs
		for a in params:
			val = params[a]
			if callable(val): val = val()
			formatargs[a] = repr(val)
		
		display = evalstring+' with: %s'%', '.join(['%s=%s'%(k, formatargs[k]) for k in formatargs.keys()]) 
		
		try:
			toeval = evalstring.format(**{k: repr(v) for (k,v) in params.items()}) 
			
			result = bool(eval(toeval))
		except Exception as e:
			self.addOutcome(BLOCKED, 'Failed to evaluate %s: %s'%(display, e), abortOnError=abortOnError)
			return
		
		if result:
			self.addOutcome(PASSED, 'Evaluating %s'%display)
		else:
			self.addOutcome(FAILED, 'Evaluating %s'%display, abortOnError=abortOnError)
		