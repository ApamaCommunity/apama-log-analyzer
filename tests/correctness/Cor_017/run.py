import time, io, calendar, random
from pysys.constants import *
from correlatorloganalyzer.analyzer_basetest import AnalyzerBaseTest

class PySysTest(AnalyzerBaseTest):
	statuslines = 1000
	def execute(self):
		
		self.copy(self.input+'/startup.log', 'logfile1.log', mappers=[lambda l: l.replace('2019-01-01 ', '2019-01-05 ')])
		self.copy(self.input+'/startup.log', 'logfile2.log', mappers=[lambda l: l.replace('2019-01-01 ', '2019-01-06 ')])

		for logfile in [1, 2]:
			logperiod = 60 if logfile==1 else 5 # status lines every minute to get a more interesting time range
			with io.open(self.output+f'/logfile{logfile}.log', 'a', encoding='utf-8') as f:
				starttime = calendar.timegm(time.strptime(f'2019-01-0{5+logfile-1} 10:06:01', '%Y-%m-%d %H:%M:%S'))
				rx = tx = 0
				rnd = random.Random(logfile)
				ceiling = {
					'iq':20000,# not a hard ceiling
					'oq':1000,
					'nc':14,
				}
				initial = {
					'rx/sec':80000/logfile,
					'tx/sec':12000/logfile,	
					
					# queues
					'iq':15000,
					'icq':2000,
					'rq':25,
					'runq':5, # almost always zero
					'oq':100,
					'nc':12,
					
					# swapping and logging
					'si':0.2,
					'so':0.3,
					'errors':3,
					'warns':10,
					
					# memory
					'pm':1024*1024*10, # kb (10GB)
					'jvm':500, # MB
					
					# EPL items
					'ls':100*1000,
					'sm':10*1000,
					'nctx':100,
				}
				d = dict(initial)

				for l in range(self.statuslines):
					for k, v in list(d.items()):
						# random walk v
						# TODO: actually better to do this based on the initial magnitude of each thing, else it'll keep decaying
						v = v+(initial[k]*rnd.uniform(-0.01, +0.01))
						
						# every now and then do a big jump; bias towards low numbers to help us get down to zero
						if rnd.random() > 0.95 and k not in {'nc'}: v = v+(initial[k]*rnd.uniform(-0.8, +0.6))
						
						if k in {'si', 'so'}:
							# usually 0, sometimes really big
							if rnd.random() > 0.98:
								v = rnd.random()*40
							elif rnd.random() > 0.75: 
								v = 0
							else:
								pass # random walk

						if k in {'iq', 'icq', 'rq', 'runq', 'oq'}: # queues are usually empty, so reset to zero most of the time, especially if previously empty
							if (d[k] == 0 and rnd.random()<0.95) or (rnd.random() > 0.99):
								v = 0

						# floor and ceiling for v
						if v < 0: v = 0.0
						if k in ceiling and v > ceiling[k]: v = ceiling[k]
						
						d[k] = v
					
					rx = rx+(d['rx/sec']*logperiod)
					tx = tx+(d['tx/sec']*logperiod)
					
					timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(starttime + (l*logperiod)))
					for i in range(int(d['warns'])):
						f.write(f'{timestamp}.111 WARN [22872] - Simulated warn message {l+1}\n')
					for i in range(int(d['errors'])):
						f.write(f'{timestamp}.222 ERROR [22872] - Simulated error message {l+1}\n')
					f.write(f"{timestamp}.888 INFO  [22872] - Correlator Status: sm={d['sm']:.0f} nctx={d['nctx']:.0f} ls={d['ls']:.0f} rq={d['rq']:.0f} iq={d['iq']:.0f} oq={d['oq']:.0f} icq={d['icq']:.0f} lcn=\"<none>\" lcq=0 lct=0.0 rx={rx:.0f} tx={tx:.0f} rt=0 nc={d['nc']:.0f} vm=22580 pm={d['pm']:.0f} runq={d['runq']:.0f} si={d['si']:0.1f} so={d['so']:0.1f} srn=\"<none>\" srq=0 jvm={d['jvm']:.0f}\n")

		self.logAnalyzer([], logfiles=[
			self.output+'/logfile1.log',
			self.output+'/logfile2.log',
			])

	def validate(self):
		self.checkForAnalyzerErrors()
		
		# X axis should include timezone
		self.assertGrep('loganalyzer_output/overview.html', expr='xlabel.: *"Local time UTC[+]03:00"')
		# no undefined values
		self.assertGrep('loganalyzer_output/overview.html', expr=r'new Date\([^)]+\),.*null', contains=False)
		self.assertGrep('loganalyzer_output/overview.html', expr=r'new Date\([^)]+\),.*,,', contains=False)
		
		self.addOutcome(INSPECT, 'Manually inspect loganalyzer_output/overview.html in a web browser')
