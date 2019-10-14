.. image:: https://travis-ci.com/ApamaCommunity/apama-log-analyzer.svg?branch=master
	:target: https://travis-ci.com/ApamaCommunity/apama-log-analyzer

.. image:: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer/branch/master/graph/badge.svg
	:target: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer

About the Apama Correlator Log Analyzer
=======================================
The log analyzer is a simple but powerful Python 3 script for analyzing Apama correlator log files and extracting useful diagnostic information. 

Features:

- `status.XXX.csv`: Extracts all periodic statistics from "Correlator Status:" lines, exporting them to an *Excel-friendly CSV file*. Columns are named in a user-friendly way, and some derived stats such as event rate are calculated. The header line contains additional metadata such as machine info, host:port and timezone. 

- `summary_status.XXX.csv`: Generates a small *summary* CSV file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check which columns might be worth graphing to chase down a memory leak or unresponsive application. 

- Calculates derived statistics including:
	
	- *rx/tx/rt rate /sec*, which are useful for determining typical receive/send rates and any anomolous periods of high/low/zero rates
	- *log lines /sec*, which is useful for detecting excessive logging
	- *warn and error lines /sec*, which is useful for identifying periods where bad things happened (error includes both ERROR and FATAL levels)
	- *memory usage deltas* (both Java and total), which are useful for identifying application or plug-in memory leaks
	- *is swapping*, which is 1 if any swapping in or out is occurring or 0 if not; the mean of this is useful for identifying how much of the time was spent swapping

- `logged_errors.txt`/`logged_warnings.txt`: Summarizes WARN and ERROR/FATAL messages across multiple log files, de-duplicating (by removing numeric bits from the message) and displaying the time range where each error/warning occurred in each log file. This makes it easy to skim past unimportant errors/warnings and spot the ones that really matter, and to correlate them with the times during which the problem occurred. 

- `overview.txt`: A textual summary of what each log file contains e.g. the time range, host:port, what features are enabled etc, which is useful for deciding which of the logs to look at in more detail, as well as for noticing important differences between the logs (e.g. different timezones or available memory/CPU).  

- `startup_stanza.XXX.log`: A copy of the first few lines of the log file that contain critical startup information such as host/port/name/configuration. If the log file does not contain startup information (perhaps it only contains recent log messages) this file will be missing. As a missing startup stanza impairs some functionality of this tool, try to obtain the missing startup information if at all possible. 

- *JSON* output mode. Most of the above can also be written in JSON format if desired, for post-processing by other scripts. Alternatively, the apamax.log_analyzer.LogAnalyzer (or LogAnalyzerTool) Python class can be imported and subclassed or used from your own Python scripts. 

- Supported Apama releases: *Apama 4.3 through to latest* (10.5+). Also works with correlator logging from `apama-ctrl`, downloaded from *Cumulocity*. 

- Licensed under the *Apache License 2.0*. 

Coming soon:

- A first official release.

Usage
=====
To run the script, simply execute the script with Python 3::

	> apamax\log_analyzer.py mycorrelator.log

On linux, make sure `python3` is on `PATH`. On Windows, ensure you have a `.py` file association for (or explicitly run it with) `py.exe` or `python.exe` from a Python 3 installation. Recent Apama releases contain Python 3. 

For more information about the meaning of the status lines, see the `List of Correlator Status Statistics <http://www.apamacommunity.com/documents/10.3.1.1/apama_10.3.1.1_webhelp/apama-webhelp/index.html#page/apama-webhelp%2Fre-DepAndManApaApp_list_of_correlator_status_statistics.html>`_ in the Apama documentation. 

Cumulocity
----------
If you're using Apama inside Cumulocity, to download the log use the App Switcher icon to go to `Administration`, then `Applications` > `Subscribed applications` > `Apama-ctrl-XXX`. Assuming Apama-ctrl is running, you'll see a `Logs` tab. You should try to get the full log - to do that click the `|<<` button to find out the date of the first entry then click `Download` select the time range from the start date to the day after today. 

Excel/CSV
---------
When you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double click the separator between any two of the column headings. 

Contributions
=============
Please feel free to add suggestions as github tickets, or to contribute a fix or feature yourself (just send a pull request). 

If you want to submit a pull request, be sure to run the existing tests, create new tests (and check the coverage is good), and do a before-and-after run of the performance tests to avoid unwittingly making it slower. 
