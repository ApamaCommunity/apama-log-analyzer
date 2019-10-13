import json, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):
		self.logAnalyzer([
			self.input+'/correlator-4.3.2.0.log', 
			self.input+'/correlator-10.3.1.0.log', 
			'--json'
		])


	def validate(self):
		self.checkForAnalyzerErrors()
		outputdir = self.output+'/loganalyzer_output'
		with io.open(outputdir+'/status.correlator-4.3.2.0.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		last_4_3_2_0=last
		self.assertEval("{last_4_3_2_0}['local datetime'].startswith('2019-09-')", last_4_3_2_0=last)
		self.assertEval("len({zero_values_in_4_3_2_0})==0", zero_values_in_4_3_2_0=[k for k in last if k!='local datetime' and last[k]<=0])

		self.assertEval("'icq' not in {last_4_3_2_0} and 'jvm' not in {last_4_3_2_0} and 'jvm delta MB' not in {last_4_3_2_0}", last_4_3_2_0=last)

		with io.open(outputdir+'/status.correlator-10.3.1.0.json') as f:
			data = json.load(f) # check it's a valid json document
		last = data['status'][-1]
		self.assertEval("{last_new}['local datetime'].startswith('2019-04-')", last_new=last)
		self.assertEval("len({zero_values_in_new})==0", zero_values_in_new=[k for k in last if (not isinstance(last[k],str) and last[k]<=0)])
		
		# check old doesn't have anything new is lacking (might need some renaming if so!)
		self.assertEval("not (set({keys_in_old_but_not_new})-set(['eq']))", keys_in_old_but_not_new=[k for k in last_4_3_2_0 if k not in last])

		self.assertEval("'jvm delta MB' in {last_new}", last_new=last)
