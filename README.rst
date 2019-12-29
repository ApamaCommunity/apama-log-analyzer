.. image:: https://travis-ci.com/ApamaCommunity/apama-log-analyzer.svg?branch=master
	:target: https://travis-ci.com/ApamaCommunity/apama-log-analyzer

.. image:: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer/branch/master/graph/badge.svg
	:target: https://codecov.io/gh/ApamaCommunity/apama-log-analyzer

About the Apama Correlator Log Analyzer
=======================================
The log analyzer is a simple but powerful Python 3 script for analyzing a set of Apama correlator log files and extracting useful diagnostic information. 

Features:

- The starting point after analyzing a log is to look at ``overview.html``, an HTML overview containing interactive 
  charts for the main statistics such as event rate and memory usage, as well as a textual summary (also in ``overview.txt``) of each 
  log file and details such as host:port, timezone, etc from the correlator's startup lines. This page also has links to 
  files such as ``logged_errors/warnings.txt`` that you'll also want to look at. The analyzer calculates and plots 
  some statistics derived from the values in the ``Correlator Status:`` lines such as:

  * **rx/tx rate /sec**, which are useful for determining typical receive/send rates and any anomalous periods of high/low/zero rates
  * **log lines /sec**, which is useful for detecting excessive logging
  * **warn and error lines /sec**, which is useful for identifying periods where bad things happened (error includes both ERROR and FATAL levels)
  * **is swapping**, which is 1 if any swapping in or out is occurring or 0 if not; swapping is the most common cause of performance problems and disconnections

  If you have several log files, pass them all to the log analyzer at the same time, as that 
  makes it easier to notice important differences between the logs (e.g. different timezones 
  or available memory/CPUs). It's also a good way of confirming which log files actually 
  contain the time period where the problem occurred!

- ``logged_errors.txt``/``logged_warnings.txt``: Summarizes **WARN and ERROR/FATAL messages** across multiple log files, de-duplicating (by removing numeric bits from the message) and displaying the time range where each error/warning occurred in each log file. 

  This makes it easy to skim past unimportant errors/warnings and spot the ones that really matter, and to correlate them with the times during which the problem occurred. 

- ``receiver_connections.XXX.csv``: Extract log messages about connections, disconnections and slowness in **receivers**. 

  This can be very useful for debugging slow receiver disconnections. 

- Supported Apama releases: **Apama 4.3 through to latest** (10.5+). Also works with correlator logging from `Apama-ctrl`, downloaded from **Cumulocity**. 

- Licensed under the **Apache License 2.0**. 


There are also some additional files which may be useful for more advanced cases:

- ``status.XXX.csv``: Extracts all periodic statistics from "Correlator Status:" lines, exporting them to an **Excel-friendly CSV file**. Columns are named in a user-friendly way, and some derived stats such as event rate are calculated. The header line contains additional metadata such as machine info, host:port and timezone. 

- ``summary_status.XXX.csv``: Generates a small **summary CSV** file containing a snapshot of values from the start/middle/end of each log, min/mean/max aggregate values, and deltas between them. This is a good first port of call, to check which columns might be worth graphing from the main status CSV to chase down a memory leak or unresponsive application. 

- ``startup_stanza.XXX.log``: A copy of the first few lines of the log file that contain critical startup information such as host/port/name/configuration. If the log file does not contain startup information (perhaps it only contains recent log messages) this file will be missing. As a missing startup stanza impairs some functionality of this tool, try to obtain the missing startup information if at all possible. 

- **JSON** output mode. Most of the above can also be written in JSON format if desired, for post-processing by other scripts. Alternatively, the ``apamax.log_analyzer.LogAnalyzer`` (or ``LogAnalyzerTool``) Python class can be imported and subclassed or used from your own Python scripts. 


Usage
=====
Download the latest stable version of the script from https://github.com/ApamaCommunity/apama-log-analyzer/releases

To run the script, simply execute the script with Python 3, specifying **all** log file(s) and/or archived log files and/or directories to be analyzed::

	> apamax\log_analyzer.py mycorrelator1.log mycorrelator2.log

On Linux, make sure ``python3`` is on ``PATH``. On Windows, ensure you have a ``.py`` file association for (or explicitly run it with) ``py.exe`` or ``python.exe`` from a Python 3 installation. Apama releases from 10.3.0 onwards contain Python 3, so an Apama command prompt/apama_env shell will have the correct ``python.exe``/``python3`` on ``PATH``. If you don't have Apama 10.3.0 available, you can download Python 3.6+ yourself. No other Python packages are required. 

Start by reviewing the ``overview.txt`` (which is also displayed on stdout when you've run the tool), then identify which logs and columns you'd like to graph (``status_summary.XXX.csv`` may help with this), and then open the relevant ``status.XXX.csv`` file in a spreadsheet such as Excel. The ``logged_errors.txt`` and ``logged_warnings.txt`` files are also worth reviewing carefully. 

For information about the meaning of the status lines which may be helpful when analyzing the csv files, see the Resources section below. 

Cumulocity
----------
If you're using Apama inside Cumulocity, to download the log use the App Switcher icon to go to **Administration**, then **Applications > Subscribed applications > Apama-ctrl-XXX**. Assuming Apama-ctrl is running, you'll see a **Logs** tab. You should try to get the full log - to do that click the ``|<<`` button to find out the date of the first entry then click **Download**, and select the time range from the start date to the day after today. 

Excel/CSV
---------
Column sizing
~~~~~~~~~~~~~
When you open a CSV file in Excel, to automatically resize all columns so that their contents can be viewed just select all (Ctrl+A), then double-click the separator between any two of the column headings. 

Keeping headers visible
~~~~~~~~~~~~~~~~~~~~~~~
In recent versions of Excel, selecting cell B2 and then **View > Split** is useful for ensuring the datetime column and header row are always visible as you scroll. 

Trendlines
~~~~~~~~~~
It may be worth adding a trendline to your Excel charts to smooth out any short-term artifacts. For example, given that status lines are logged every 5 seconds, a moving average trendline with a period of 6 samples (=30s), 12 samples (=60s) or 24 samples (=2m) can be useful when graphing the send (tx) rate in cases where the rate appears to be modal over two or three values (as a result of the interaction between the 5 second log sample period and the batching of message sending within the correlator). 

Importing CSVs in a non-English locale (e.g. Germany)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unfortunately the CSV file format (and Excel in particular) has fairly poor support for use in locales such as German that have different decimal, thousand and date formats to the US/UK format generated by this tool. It is therefore necessary to explicitly tell Excel how to interpret the numeric CSV columns. In Excel 365, the steps are:

  #. Open Excel (it should be displaying an empty spreadsheet; don't open the CSV file yet).
  #. On the **Data** tab click **From Text/CSV** and select the CSV file to be imported.
  #. Ensure the **Delimiter** is set to **Comma**, then click **Edit**.
  #. On the **Home** tab of the Power Query Editor dialog, click **Use First Row as Headers**.
  #. Select all columns that contain numbers. To do this click the heading for ``epoch secs``, scroll right until you see ``# metadata:`` then hold down **SHIFT** and click the column before ``# metadata:``.
  #. (Optional: if you plan to use any values containing non-numeric data (e.g. slowest consumer or context name) then deselect those columns by holding down **CTRL** while clicking them; otherwise non-numeric values will show up as _Error_ or blank).
  #. Right-click the selected column headings, and choose **Change Type > Using Locale...**.
  #. Set the Data Type to **Decimal Number** and Locale to **English (Australia)** (or United States; any English locale should be fine), then click **OK**.
  #. On the **Home** tab click **Close & Load**.

Resources
=========

From the Apama documentation:

  - `List of Correlator Status Statistics <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp%2Fre-DepAndManApaApp_list_of_correlator_status_statistics.html>`_ - for understanding the meaning of the statistics available

  - `Inspecting correlator state <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp%2Fre-DepAndManApaApp_inspecting_correlator_state.html%23>`_ - for using the engine_inspect tool to get detailed information on the number of monitor instances, listeners, etc, which can help to identify application memory leaks

  - `Shutting down and managing components <http://www.apamacommunity.com/documents/10.5.0.2/apama_10.5.0.2_webhelp/apama-webhelp/index.html#page/apama-webhelp/re-DepAndManApaApp_shutting_down_and_managing_components.html>`_ and its child topics - contain information on using `dorequest` to get detailed memory/CPU profiles, a string representation of the correlator queues, and various enhanced logging options



Contributions
=============
Please feel free to add suggestions as GitHub tickets, or to contribute a fix or feature yourself (just send a pull request). 

If you want to submit a pull request, be sure to run the existing tests, create new tests (and check the coverage is good), and do a before-and-after run of the performance tests to avoid unwittingly making it slower. 
