####NAME
<dl>
    <dd>pydan - tool to interface with Shodan API</dd>
</dl>

----

####SYNOPSIS
```pydan.py [OPTION]... (-q STRING | --host IP | -e STRING) -o FILE```

----

####DESCRIPTION

pydan is a tool that provides a way to easily use the Shodan API (using your own API key) and try to perform some analysis to find interesting and possibly vulnerable devices.

To use pydan you will need to download and install the [Shodan Python API]. The last time I checked PyPI didn't have the latest version of the api, so I suggest cloning/downloading the api from the Github page and installing via: ```python setup.py install```

&nbsp;
<dl>
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;-h, --help</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;shows help message</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;-k KEY, --key KEY</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;Shodan API key</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;-o FILE, --output FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;Write output to FILE</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;-x FILE, --xml FILE</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;Name of XML file to import and perform operations on locally</dd>
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;-v, --verbose</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;verbose mode</dd>
    
    
    <dt>&nbsp;&nbsp;&nbsp;&nbsp;</dt>
    <dd>&nbsp;&nbsp;&nbsp;&nbsp;</dd>
</dl>

----

[Shodan Python API]: https://github.com/achillean/shodan-python
