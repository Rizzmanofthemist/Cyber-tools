Lightweight toolkit for VirusTotal IoC reputation lookups.

Not intended for use in business processes.

This repository contains:
1. A class constructer for generating the IoC object
2. A parent main function to instantiate and call the object submission function

To ultilize the tool, first a VT API key must be obtained.
This is available through account signup (public API key) on https://www.virustotal.com/.

Once key has been obtained, it is recommended to set the key value in enviroment variable.
On Windows OS, this can be done through CMD using the <set> command:

    set VTAPI='yourAPIKey'
    
On Linux (Debian), the terminal command <env> can be used:

    env VTAPI='yourAPIKey'
    
Once the enviroment variables are set, valid HTTP requests can be made to the VT API gateway.

The tool should be ran using the VT_dataSubmitProcess.py as the main function.

To run the tool, it is recommended to download the python scripts and the target log file - assumed csv, into the same folder.
Then sumply load the VT_dataSubmitProcess.py through an import statement:

import VT_dataSubmitProcess.py

The program would then execute, prompting for input file name and column of IoC data for submission analysis.


