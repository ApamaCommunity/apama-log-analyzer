.. image:: https://travis-ci.com/ben-spiller/correlator-log-analyzer.svg?branch=master
	:target: https://travis-ci.com/ben-spiller/correlator-log-analyzer

.. image:: https://codecov.io/gh/ben-spiller/correlator-log-analyzer/branch/master/graph/badge.svg
	:target: https://codecov.io/gh/ben-spiller/correlator-log-analyzer

About the Apama Correlator Log Analyzer
=======================================
The log analyzer is a simple but powerful Python script for analyzing Apama correlator log files and extracting useful diagnostic information. 

Features:

- `status_XXX.csv`: Extracts all periodic statistics from "Correlator Status:" lines, exporting them to an *Excel-friendly CSV file*. Columns are named in a user-friendly way, and some derived stats such as event rate are calculated. 
- `summary_XXX.csv`: Generates a small *summary* CSV file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check which columns might be worth graphing to chase down a memory leak or unresponsive application. 
- `status_summary_XXX.json`: Optionally, the status line extraction can also write a json file, which could be handy if you want to write a script to process them.
- Calculates derived statistics including:
	
	- *rx/tx/rt rate /sec*, which are useful for determining typical receive/send rates and any anomolous periods of high/low/zero rates
	- *log lines /sec*, which is useful for detecting excessive logging
	- *warn and error lines /sec*, which is useful for identifying periods where bad things happened (error includes both ERROR and FATAL levels)
	- *memory usage deltas* (both Java and total), which are useful for identifying application or plug-in memory leaks
	- *is swapping*, which is 1 if any swapping in or out is occurring or 0 if not; the mean of this is useful for identifying how much of the time was spent swapping
	
- Supported Apama releases: *Apama 4.3 through to latest* (10.5+). Also works with correlator logging from `apama-ctrl`, downloaded from *Cumulocity*. 
- Licensed under the *Apache License 2.0*. 

Coming soon:

- A first official release.
- Ability to extract and sort/categorize ERROR and WARN messsages. 
- Improved support for multiple log files including extraction of key information about the host/port/correlator name and duration of each log file. 

Usage
=====
To run the script, simply execute::

	> python3 apamax\log_analyzer.py mycorrelator.log

Cumulocity
----------
If you're using Apama inside Cumulocity, to download the log use the App Switcher icon to go to `Administration`, then `Applications` > `Subscribed applications` > `Apama-ctrl-XXX`. Assuming Apama-ctrl is running, you'll see a `Logs` tab. You should try to get the full log - to do that click the `|<<` button to find out the date of the first entry then click `Download` select the time range from the start date to the day after today. 

Excel/CSV
---------
When you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double click the separator between any two of the column headings. 

Contributions
=============
Please feel free to add suggestions as github tickets, or to contribute a fix or feature yourself (just send a pull request). 
