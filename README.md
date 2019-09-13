[![Build Status](https://travis-ci.com/ben-spiller/correlator-log-analyzer.svg?branch=master)](https://travis-ci.com/ben-spiller/correlator-log-analyzer)
[![codecov](https://codecov.io/gh/ben-spiller/correlator-log-analyzer/branch/master/graph/badge.svg)](https://codecov.io/gh/ben-spiller/correlator-log-analyzer)

# correlator-log-analyzer
Python script for analyzing Apama correlator log files and extracting useful diagnostic information. 

To run the script from this directory, simply execute:

	> python3 apamax\log_analyzer.py

Excel tip: when you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double click the separator between any two of the column headings. 

# Features
- status_XXX.csv: Extracts all values from "Correlator Status:" lines, exporting them to an Excel-friendly CSV file (and also optionally to json, if you want to write a script to process them). 
- summary_XXX.csv: Generates a small summary CSV file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check