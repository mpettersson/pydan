<!---
The formatting in this README is godawful. I welcome anyone to fix it.
This is why I'm not a web developer
-->
####NAME

&nbsp;&nbsp;&nbsp;&nbsp;pydan - tool to interface with Shodan API</dd>

----

####SYNOPSIS
&nbsp;&nbsp;&nbsp;&nbsp;```pydan.py [OPTION]... (-q STRING | --host IP | -e STRING) -o FILE```

----

####DESCRIPTION

&nbsp;&nbsp;&nbsp;&nbsp;pydan is a tool that provides a way to easily use the Shodan API (using your own API key) and try to perform some analysis to find &nbsp;&nbsp;&nbsp;&nbsp;interesting and possibly vulnerable devices.

&nbsp;&nbsp;&nbsp;&nbsp;To use pydan you will need to download and install the [Shodan Python API]. The last time I checked PyPI didn't have the latest &nbsp;&nbsp;&nbsp;&nbsp;version of the api, so I suggest cloning/downloading the api from the Github page and installing via: ```python setup.py install```

######&nbsp;&nbsp;&nbsp;&nbsp;OPTIONS
<dl>
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;@FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Name of file to read line seperated arguments from. If an argument is supplied in FILE and at the command line, the value &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;at the command line is used.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-h, --help</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Shows help message.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-k KEY, --key KEY</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Shodan API key.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-o FILE, --output FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(REQUIRED) Write output to FILE.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-x FILE, --xml FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Name of XML file to import and perform operations on locally. If this option isn't given then an api key must be supplied. This &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;option allows pydan to perform some analysis on results exported from Shodan's website (to save your query count).</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;--fingerprint</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(EXPERIMENTAL) Attempt to fingerprint devices based on their banner's. This option will use the Shodan API to try to figure &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;out what type of device something is based on its banner response. (incompatible with -e option)</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;--xlookup</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Attempt to find exploits on the types of devices found. This option will try to find possible exploits for the various types of &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;servers found from a query. (incompatible with -e option)</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-v, --verbose</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Verbose mode.</dd>
</dl>

######&nbsp;&nbsp;&nbsp;&nbsp;ACTIONS
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The following are the main actions pydan can perform. These are mutually exclusive and atleast one must be chosen.
<dl>
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-q STRING, --query STRING</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;String used to query Shodan.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;--host IP</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;IP of single host to lookup.</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-e STRING, --exploit STRING</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;String used to query for exploits.</dd>
</dl>

----

####EXAMPLES
&nbsp;&nbsp;&nbsp;&nbsp;TODO

[Shodan Python API]: https://github.com/achillean/shodan-python
