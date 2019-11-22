3.2
---
- Add ``receiver_connections.XXX.csv`` which summarizes connections, disconnections and slow receivers.
- Improve heuristics for grouping related warn/error messages to include filtering of stringified events, and of text at least 80 characters through the string that's following a colon
- Add ``README.rst`` instructions for opening CSV files in non-English locales such as German. Unfortunately it's quite an involved process. 

3.1
---
- Fix bug resulting in error when log analysis takes more than 10s.
- Add support for ``.gz`` files.
- Add special-case to parse ``apama-ctrl-*`` log files that don't end with .log. 

3.0
---

- First version of the latest incarnation of this script. Supports status CSV extraction, error/warning summary and overview derived from startup stanza. 