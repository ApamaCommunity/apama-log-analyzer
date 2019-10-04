import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	initialvalues = {
		'sm':1,
		'nctx':2,
		'ls':3,
		'rq':4,
		'lcn':"<none>",
		'lct':5.5,
		'si':6.6,
		'so':1.1,
		'jvm':7*1024,
		'rx':8,
		'tx':9,
		'mynewstatus':10,
	}
	def execute(self):
		for totallines in 1, 2, 8, 20:
			with io.open(self.output+f'/generated-log-{totallines:02}.log', 'w', encoding='utf-8') as f:
				for l in range(totallines):
					f.write(f'2019-04-08 13:00:{l:02}.111 INFO  [22872] - Correlator Status: ')
					for k in self.initialvalues:
						val = self.initialvalues[k]
						if l > 0 and not isinstance(val, str):
							val = val*(10**l)
							if k=='si': val = 0.5 if l%5==0 else 0.0
							if k=='so': val = 0.9 if l%10==0 else 0.0
						f.write(f'{k}={val} ')
					# no need to test everything individually
					f.write('rt=0 nc=0 vm=3 pm=4 runq=0  somethingelse=123\n')
				
			
		# run with multiple files to check we don't get errors for small numbers of inputs, 
		# and that they don't interfere with each other
		self.logAnalyzer(['--statusjson'], logfiles=[
			self.output+'/generated-log-20.log',
			self.output+'/generated-log-08.log',
			self.output+'/generated-log-02.log',
			self.output+'/generated-log-01.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()

		# check we include some metadata in the summary
		self.assertGrep('loganalyzer_output/summary_generated-log-08.csv', expr='# metadata.*,analyzer=v[0-9]')
		self.assertGrep('loganalyzer_output/summary_generated-log-08.json', expr='"analyzer":.*"v[0-9]')

		self.assertGrep('loganalyzer_output/summary_generated-log-08.json', literal=True, 
			# check for ordering of key, and that the right things are present
			expr='{"statistic": "0% (start)", "datetime": "2019-04-08 13:00:00.111", "epoch secs": 1554728400.111, "interval secs": 0.0, "line num": 1, ')

		self.assertGrep('loganalyzer_output/summary_generated-log-08.json', literal=True, 
			# check it's represented as a float
			expr='"interval secs": 1.0')
			
		self.assertGrep('loganalyzer_output/summary_generated-log-08.json', expr='mynewstatus')
		self.assertGrep('loganalyzer_output/summary_generated-log-08.json', expr='somethingelse')

		with io.open(self.output+'/loganalyzer_output/summary_generated-log-08.json') as f:
			s = json.load(f)['status']
		
		def findstat(statistic):
			for x in s:
				if x['statistic'] == statistic: return x
			assert False, 'Not found: %s'%statistic
		
		self.assertEval("{status0pc_linenum}  == 1", status0pc_linenum=findstat('0% (start)')['line num'])
		self.assertEval("{status25pc_linenum} == 2", status25pc_linenum=findstat('25%')['line num'])
		self.assertEval("{status50pc_linenum} == 4", status50pc_linenum=findstat('50%')['line num'])
		self.assertEval("{status75pc_linenum} == 6", status75pc_linenum=findstat('75%')['line num'])
		self.assertEval("{status100pc_linenum} == 8", status100pc_linenum=findstat('100% (end)')['line num'])

		self.assertEval("{status0pc_rq}   == 4", status0pc_rq=findstat('0% (start)')['rq=queued route'])
		self.assertEval("{status25pc_rq}  == 4*10", status25pc_rq=findstat('25%')['rq=queued route'])
		self.assertEval("{status50pc_rq}  == 4*1000", status50pc_rq=findstat('50%')['rq=queued route'])
		self.assertEval("{status75pc_rq}  == 4*100000", status75pc_rq=findstat('75%')['rq=queued route'])
		self.assertEval("{status100pc_rq} == 4*10000000", status100pc_rq=findstat('100% (end)')['rq=queued route'])

		self.assertEval("{min_rq} == 4", min_rq=findstat('min')['rq=queued route'])
		self.assertEval("{max_rq} == 4*10000000", max_rq=findstat('max')['rq=queued route'])
		self.assertEval("{mean_rq} == {expected}", mean_rq=findstat('mean')['rq=queued route'], expected=math.trunc(sum([4*(10**n) for n in range(8)])/8.0))

		self.assertEval("{min_swapping} == 0", min_swapping=findstat('min')['is swapping'])
		self.assertEval("{max_swapping} == 1", max_swapping=findstat('max')['is swapping'])
		self.assertEval("{mean_swapping} == 2/8.0", mean_swapping=findstat('mean')['is swapping'])

		self.assertEval("{min_mean_max_datetime} == ''", min_mean_max_datetime=findstat('min')['datetime']+findstat('mean')['datetime']+findstat('max')['datetime'])

		# user-defined statuses
		self.assertEval("{min_mynewstatus} == 10", min_mynewstatus=findstat('min')['mynewstatus'])
		self.assertEval("{max_mynewstatus} == 100*1000*1000", max_mynewstatus=findstat('max')['mynewstatus'])
		
		self.assertEval("{mean_somethingelse} == 123", mean_somethingelse=findstat('mean')['somethingelse'])

		# special check for JVM as it's a floating point number and we special-case those
		self.assertEval("{min_jvm} == 7", min_jvm=findstat('min')['jvm=Java MB'])
		self.assertEval("{max_jvm} == 70*1000*1000", max_jvm=findstat('max')['jvm=Java MB'])
		self.assertEval("{mean_jvm} == {expected}", mean_jvm=findstat('mean')['jvm=Java MB'], expected=sum([7*(10**n) for n in range(8)])/8.0)

		self.assertEval("{mean_jvm_delta} == {expected}", mean_jvm_delta=findstat('mean')['jvm delta MB'], expected=math.trunc(sum([(70-7)*(10**(n-1)) for n in range(8)])/8.0))

		# check CSV file has the annotated headinghs
		self.assertGrep('loganalyzer_output/status_generated-log-08.csv',  expr=',rq=queued route,')

		# formatting of final JVM in CSV
		self.assertGrep('loganalyzer_output/status_generated-log-08.csv',  expr='13:00:00,.*,7.00,')
		self.assertGrep('loganalyzer_output/summary_generated-log-08.csv', expr='13:00:00,.*,7.00,')
		self.assertGrep('loganalyzer_output/status_generated-log-08.csv',  expr='13:00:07,.*"70,000,000"')
		self.assertGrep('loganalyzer_output/summary_generated-log-08.csv', expr='13:00:07,.*"70,000,000"')

		# sanity check that min<=mean<=max
		for k in findstat('min'):
			if isinstance(findstat('min')[k], str): continue
			if round(findstat('min')[k], 3) > round(findstat('mean')[k], 3): # allow a bit of rounding error
				self.addOutcome(FAILED, f"min ({findstat('min')[k]}) > mean ({findstat('mean')[k]}) for '{k}'")
			if findstat('mean')[k] > findstat('max')[k]:
				self.addOutcome(FAILED, f"mean ({findstat('mean')[k]}) > max ({findstat('max')[k]}) for '{k}'")
			
