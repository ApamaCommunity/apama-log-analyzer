.. image:: https://travis-ci.com/ben-spiller/correlator-log-analyzer.svg?branch=master
	:target: https://travis-ci.com/ben-spiller/correlator-log-analyzer

.. image:: https://codecov.io/gh/ben-spiller/correlator-log-analyzer/branch/master/graph/badge.svg
	:target: https://codecov.io/gh/ben-spiller/correlator-log-analyzer

About the Apama Correlator Log Analyzer
=======================================
The log analyzer is a simple but powerful Python script for analyzing Apama correlator log files and extracting useful diagnostic information. 

Features:

- `status_XXX.csv`: Extracts all values from "Correlator Status:" lines, exporting them to an Excel-friendly CSV file. 
- `summary_XXX.csv`: Generates a small summary CSV file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check which columns might be worth graphing to chase down a memory leak or unresponsive application. 
- `status/summary_XXX.json`: Optionally, the status line extraction can also write a json file, which could be handy if you want to write a script to process them.
- Supported Apama releases: Currently the focus is on 10.3+, but planned to add testing for older versions soon. 
- Licensed under the Apache License 2.0. 

Coming soon:

- A first official release.
- Ability to extract and sort/categorize ERROR and WARN messsages. 
- Improved support for multiple log files including extraction of key information about the host/port/correlator name and duration of each log file. 

Usage
=====
To run the script, simply execute::

	> python3 apamax\log_analyzer.py mycorrelator.log

Cumulocity tip
--------------
If you're using Apama inside Cumulocity, to download the log use the App Switcher icon to go to `Administration`, then `Applications` > `Subscribed applications` > `Apama-ctrl-XXX`. Assuming Apama-ctrl is running, you'll see a `Logs` tab. You should try to get the full log - to do that click the `|<<` button to find out the date of the first entry then click `Download` select the time range from the start date to the day after today. 

Excel CSV tip
-------------
When you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double click the separator between any two of the column headings. 

Contributions
=============
Please feel free to add suggestions as github tickets, or to contribute a fix or feature yourself (just send a pull request). 
