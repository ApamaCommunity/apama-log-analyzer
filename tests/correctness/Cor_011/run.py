import io
import datetime
import json
import math
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	def execute(self):			
		self.logAnalyzer(['--json'], logfiles=['correlator-java-errors.log'], stdouterr='loganalyzer_java')
		self.logAnalyzer(['--json'], logfiles=['correlator-epl-errors.log', 'correlator-crash.log'], stdouterr='loganalyzer_nonjava')

	def validate(self):
		self.checkForAnalyzerErrors(stdouterr='loganalyzer_java')
		self.checkForAnalyzerErrors(stdouterr='loganalyzer_nonjava')
		
		self.assertDiff('loganalyzer_java_output/errors.txt', 'ref-java-errors.txt')
		self.assertDiff('loganalyzer_java_output/warnings.txt', 'ref-java-warnings.txt')
		self.assertDiff('loganalyzer_nonjava_output/errors.txt', 'ref-nonjava-errors.txt')