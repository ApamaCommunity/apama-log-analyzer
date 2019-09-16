import glob
import subprocess
import logging, io, sys
import multiprocessing
from pysys.utils.perfreporter import *
from pysys.utils.logutils import ColorLogFormatter
from pysys.utils.logutils import stdoutPrint

log = logging.getLogger('perfreporter')

class CustomPerfReporter(CSVPerformanceReporter):
	def getRunDetails(self):
		d = super(CustomPerfReporter, self).getRunDetails()
		
		d['version'] = self.runner.getExprFromFile(self.project.logAnalyzerScript, "__version__ = '(.+)'")
		
		try:
			gitcommit = subprocess.check_output(['git', 'show', '-s', '--format=%h']).strip().decode('utf-8')
			assert '\n' not in gitcommit, gitcommit
		except Exception as ex:
			log.info('Failed to get git commit hash: %s', ex)
			raise
		else:
			d['gitCommit'] = gitcommit

		#d['cpuCount'] = multiprocessing.cpu_count()		
		d['platform'] = sys.platform
		return d
