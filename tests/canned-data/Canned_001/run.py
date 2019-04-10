import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		# default settings i.e. output=None
		self.logAnalyzer([self.input+'/mycorrelator.log', '--statusjson'], output=None)


	def validate(self):
		def splitcsvline(l):
			l = l.split(',')
			r = []
			inquotes = False
			for x in l:
				if inquotes:
					r[-1] += ','+x
					if x.endswith('"'): inquotes = False
				else:
					r.append(x)
					if x.startswith('"'): inquotes = True
			return r
	
		self.checkForAnalyzerErrors()
		self.assertGrep('loganalyzer.err', expr='Apama correlator log analyzer v[0-9].*')
		self.assertGrep('loganalyzer.err', expr='Starting analysis of mycorrelator.log')
		self.assertGrep('loganalyzer.err', expr='Completed analysis in [0-9]+ seconds')

		outputdir = self.output+'/log_analyzer_mycorrelator'
		self.assertPathExists(outputdir)
		self.log.info('Created files: %s'%sorted(os.listdir(outputdir)))
		with io.open(outputdir+'/status_mycorrelator.json') as f:
			json.load(f) # check it's a valid json document
		
		# check CSV is sane
		with io.open(outputdir+'/status_mycorrelator.csv', encoding='utf-8') as f:
			csvlines = f.readlines()
		self.assertEval('{header_cols} == {row_cols}', 
			header_cols=len(csvlines[0].split(',')), 
			row_cols=len(splitcsvline(csvlines[1])))
		header = csvlines[0].strip().split(',')
		self.assertEval('{header}.startswith("#")', header=csvlines[0])
		
		self.assertEval('{output_columns} == {log_file_status_items}+{extra_cols}', 
			output_columns=len(header),
			log_file_status_items=self.getExprFromFile(self.input+'/mycorrelator.log', 'Correlator Status: .*').count('='), 
			extra_cols=2 # dateline, line number
			)
		
		self.logFileContents(outputdir+'/status_mycorrelator.csv')
		
		self.assertGrep(outputdir+'/status_mycorrelator.json', expr='"line num": 76, .*"ls[^"]*": 50000,')
		self.assertGrep(outputdir+'/status_mycorrelator.json', expr='"line num": 77, .*"ls[^"]*": 10,')
		
		# JMS not enabled in this correlator
		self.assertGrep(outputdir+'/status_mycorrelator.csv', expr='(jms|JMS).*', contains=False)
		
		self.assertLineCount(outputdir+'/status_mycorrelator.csv', expr='.', condition='==1+3')
		self.assertLineCount(outputdir+'/status_mycorrelator.json', expr='"datetime":', condition='==3')

		self.assertGrep(outputdir+'/status_mycorrelator.csv', expr='[?]', contains=False)
