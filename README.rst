.. image:: https://travis-ci.com/ApamaCommunity/apama-log-analyzer.svg?branch=master
	:target: https://travis-ci.com/ApamaCommunity/apama-log-analyzer

.. image:: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer/branch/master/graph/badge.svg
	:target: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer

About the Apama Correlator Log Analyzer
=======================================
The log analyzer is a simple but powerful Python 3 script for analyzing Apama correlator log files and extracting useful diagnostic information. 

Features:

- ``overview.txt``: A textual summary of the time range covered by each log file, some key details from the correlator's startup lines (e.g. host:port, timezone), and a summary of statistics such as memory usage, swapping, and error/warn counts.  This helps you decide which of the logs to look at in more detail, as well as for noticing important differences between the logs (e.g. different timezones or available memory/CPUs). It's also a good way of confirming your log actually contains the time period where the problem occurred!

- ``status.XXX.csv``: Extracts all periodic statistics from "Correlator Status:" lines, exporting them to an *Excel-friendly CSV file*. Columns are named in a user-friendly way, and some derived stats such as event rate are calculated. The header line contains additional metadata such as machine info, host:port and timezone. 

- ``summary_status.XXX.csv``: Generates a small *summary* CSV file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check which columns might be worth graphing from the main status csv to chase down a memory leak or unresponsive application. 

- Calculates derived statistics including:
	
	- *rx/tx/rt rate /sec*, which are useful for determining typical receive/send rates and any anomolous periods of high/low/zero rates
	- *log lines /sec*, which is useful for detecting excessive logging
	- *warn and error lines /sec*, which is useful for identifying periods where bad things happened (error includes both ERROR and FATAL levels)
	- *memory usage deltas* (both Java and total), which are useful for identifying application or plug-in memory leaks
	- *is swapping*, which is 1 if any swapping in or out is occurring or 0 if not; the mean of this is useful for identifying how much of the time was spent swapping

- ``logged_errors.txt``/``logged_warnings.txt``: Summarizes WARN and ERROR/FATAL messages across multiple log files, de-duplicating (by removing numeric bits from the message) and displaying the time range where each error/warning occurred in each log file. This makes it easy to skim past unimportant errors/warnings and spot the ones that really matter, and to correlate them with the times during which the problem occurred. 

- ``receiver_connections.XXX.csv``: Extract log messages about connections, disconnections and slowness in receivers.

- ``startup_stanza.XXX.log``: A copy of the first few lines of the log file that contain critical startup information such as host/port/name/configuration. If the log file does not contain startup information (perhaps it only contains recent log messages) this file will be missing. As a missing startup stanza impairs some functionality of this tool, try to obtain the missing startup information if at all possible. 

- *JSON* output mode. Most of the above can also be written in JSON format if desired, for post-processing by other scripts. Alternatively, the apamax.log_analyzer.LogAnalyzer (or LogAnalyzerTool) Python class can be imported and subclassed or used from your own Python scripts. 

- Supported Apama releases: *Apama 4.3 through to latest* (10.5+). Also works with correlator logging from `apama-ctrl`, downloaded from *Cumulocity*. 

- Licensed under the *Apache License 2.0*. 

Coming soon:

- A first official release.

Usage
=====
Download the latest stable version of the script from https://github.com/ApamaCommunity/apama-log-analyzer/releases

To run the script, simply execute the script with Python 3::

	> apamax\log_analyzer.py mycorrelator.log

On linux, make sure `python3` is on `PATH`. On Windows, ensure you have a `.py` file association for (or explicitly run it with) `py.exe` or `python.exe` from a Python 3 installation. Apama releases from 10.3.0 onwards contain Python 3, so an Apama command prompt/apama_env shell will have the correct `python.exe`/`python3` on `PATH`. If you don't have Apama 10.3.0 available, you can download Python 3.6+ yourself. No other Python packages are required. 

Start by reviewing the `overview.txt` (whcih is also displayed on stdout when you've run the tool), then identify which logs and columns you'd like to graph (`status_summary.XXX.csv` may help with this), and then open the relevant `status.XXX.csv` file in a spreadsheet such as Excel. The `logged_errors.txt` and `logged_warnings.txt` files are also worth reviewing carefully. 

For information about the meaning of the status lines which may be helpful when analyzing the csv files, see the Resources section below. 

Cumulocity
----------
If you're using Apama inside Cumulocity, to download the log use the App Switcher icon to go to `Administration`, then `Applications` > `Subscribed applications` > `Apama-ctrl-XXX`. Assuming Apama-ctrl is running, you'll see a `Logs` tab. You should try to get the full log - to do that click the `|<<` button to find out the date of the first entry then click `Download` select the time range from the start date to the day after today. 

Excel/CSV
---------
When you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double click the separator between any two of the column headings. 

In recent versions of Excel, selecting cell B2 and then View > Split is useful for ensuring the datetime and header row are always visible as you scroll. 

It may be worth adding a trendline to your Excel graphs to smooth out any short-term artifacts. For example, given that status lines are logged every 5 seconds, a moving average trendline with a period of 6 samples (=30s), 12 samples (=60s) or 24 samples (=2m) can be useful when graphing the send (tx) rate in cases where the rate appears to be modal over two or three values (as a result of the interaction between the 5 second log sample period and the batching of message sending within the correlator). 

Resources
=========

From the Apama documentation:

  - `List of Correlator Status Statistics <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp%2Fre-DepAndManApaApp_list_of_correlator_status_statistics.html>`_ - for understanding the meaning of the statistics available

  - `Inspecting correlator state <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp%2Fre-DepAndManApaApp_inspecting_correlator_state.html%23>`_ - for using the engine_inspect tool to get detailed information on the number of monitor instances, listeners etc, which can help to identify application memory leaks

  - `Shutting down and managing components <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp/re-DepAndManApaApp_shutting_down_and_managing_components.html>`_ and its child topics - contain information on using `dorequest` to get detailed memory/CPU profiles, a string representation of the correlator queues, and various enhanced logging options



Contributions
=============
Please feel free to add suggestions as GitHub tickets, or to contribute a fix or feature yourself (just send a pull request). 

If you want to submit a pull request, be sure to run the existing tests, create new tests (and check the coverage is good), and do a before-and-after run of the performance tests to avoid unwittingly making it slower. 
