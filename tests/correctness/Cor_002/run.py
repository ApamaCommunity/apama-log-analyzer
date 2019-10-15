import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer(['--json'], logfiles=['mycorrelator.log'])

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

		outputdir = self.output+'/loganalyzer_output'
		with io.open(outputdir+'/status.mycorrelator.json') as f:
			json.load(f) # check it's a valid json document
		
		# check CSV is sane
		with io.open(outputdir+'/status.mycorrelator.csv', encoding='utf-8') as f:
			f.readline() # strip off the separator
			csvlines = f.readlines()
		header = csvlines[0].strip().split(',')
		
		METADATA_START = '# metadata: '
		if METADATA_START in header:
			header = header[:header.index(METADATA_START)]

		with io.open(self.output+'/csv_sample.txt', 'w', encoding='utf-8') as fd:
			i = 0
			for h in header:
				fd.write('%s : %s\n'%(h, splitcsvline(csvlines[2])[i]))
				i+=1
				
		self.assertDiff('csv_sample.txt', 'ref_csv_sample.txt', sort=True) # to show if it's just an ordering change
		self.assertDiff('csv_sample.txt', 'ref_csv_sample.txt') 
		
		self.assertGrep(outputdir+'/status.mycorrelator.csv', expr='[?]', contains=False)

		self.logFileContents('csv_sample.txt', maxLines=0)
		self.logFileContents(outputdir+'/status.mycorrelator.csv')
		
		