import time, io
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	statuslines = 500
	def execute(self):
		
		with io.open(self.output+f'/generated-log-nostartup.log', 'w', encoding='utf-8') as f:
			for l in range(self.statuslines):
				timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(1546398000 + l))+'.123'
				f.write(f'{timestamp} ERROR [22872] - Simulated error message {l+1}\n')
				f.write(f'{timestamp} INFO  [22872] - Correlator Status: sm=0 nctx=1 ls={l+1} rq=0 iq=0 oq=0 icq=0 lcn="<none>" lcq=0 lct=0.0 rx=0 tx=0 rt=0 nc=0 vm=22580 pm=25312 runq=0 si=0.4 so=0.0 srn="<none>" srq=0 jvm=0\n')

		self.copy(self.input+'/startup.log', 'generated-log-startup.log')
		with io.open(self.output+'/generated-log-startup.log', 'a', encoding='utf-8') as f:
			with io.open(self.output+f'/generated-log-nostartup.log', 'r', encoding='utf-8') as sf:
				f.write(sf.read())

		self.logAnalyzer(['--json', '--skip', '20.001%'], logfiles=[
			self.output+'/generated-log-nostartup.log',
			self.output+'/generated-log-startup.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		expected = 80*5
		self.assertLineCount('loganalyzer_output/status.generated-log-nostartup.csv', expr='^2019', condition=f'in [{expected}, {expected}-1]')
		self.assertEval('{logged_errors_nostartup} == {expected}', logged_errors_nostartup=int(self.getExprFromFile('loganalyzer_output/logged_errors.txt', '([0-9]+) errors in generated-log-nostartup')), expected=expected)

		self.assertEval('80*5 < {logged_errors_startup} < 500', logged_errors_startup=int(self.getExprFromFile('loganalyzer_output/logged_errors.txt', '([0-9]+) errors in generated-log-startup')), expected=expected)

		# check we got the startup stanza before skipping
		self.assertGrep('loganalyzer_output/overview.txt', expr='Instance:.*Apama Designer Correlator')
		
		# check that the time range for the startup log excludes the startup stanza and initial status value(s)
		self.assertGrep('loganalyzer_output/status.generated-log-startup.json', expr='"local datetime": "2019-01-01 ', contains=False)
		self.assertGrep('loganalyzer_output/status.generated-log-nostartup.json', expr='"local datetime": "2019-01-02 03:00:', contains=False)
		self.assertGrep('loganalyzer_output/status.generated-log-startup.json', expr='"local datetime": "2019-01-02 03:00:', contains=False)
