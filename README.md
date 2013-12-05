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
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-h, --help</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;shows help message</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-k KEY, --key KEY</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Shodan API key</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-o FILE, --output FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;write output to FILE</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-x FILE, --xml FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Name of XML file to import and perform operations on locally. If this option isn't given then an api key must be supplied. This option allows pydan to perform some analysis on results exported from Shodan's website (to save your query count).</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-v, --verbose</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;verbose mode</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-c FILE, --config FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;name of file from which to load options</dd>
</dl>

######&nbsp;&nbsp;&nbsp;&nbsp;ACTIONS
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The following are the main actions pydan can perform. These are mutually exclusive and atleast one must be chosen.
<dl>
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-q STRING, --query STRING</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;string used to query Shodan</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;--host IP</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ip of host to lookup</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-e STRING, --exploit STRING</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;string used to query for exploits</dd>
</dl>

----

####EXAMPLES
TODO

[Shodan Python API]: https://github.com/achillean/shodan-python
