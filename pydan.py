import optparse
import signal
from shodan import WebAPI
import xml.etree.ElementTree as ET

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)

def query(query, local=False):
    if local:
        #TODO: Locally query XML data
    else:
        print "Searching Shodan...",
        try:
            results = api.search(query)
        except Exception, e:
            print "Failed! (Error: %s)" % e
        
        print "Success!"
        dictToXMLTree(results)

def lookupHost(ip):
    print "Looking up host on Shodan...",
    try:
        host = api.host(ip)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    
    print """
        IP: %s
        Country: %s
        City: %s
    """ % (host['ip'], host.get('country', None), host.get('city', None))

    for item in host['data']:
        print """
                Port: %s
                Banner: %s

        """ % (item['port'], item['banner'])
    #TODO:Merge results into XML tree

def findExploits(query):
    print "Searching for exploits...",
    try:
        exploits = api.exploits.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    #TODO:Merge results into XML tree

def formatFilename(fname):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = ''.join(c for c in fname if c in valid_chars)
    filename = filename.replace(' ','_')
    if not filename.endswith(".xml"):
        filename += ".xml"
    return filename

def exportResults(tree, fname):
    tree.write(fname)

def dictToXMLTree(dict):
    global out_root
    for host in dict['matches']:
        out_root.append(ET.Element("host",host))

if __name__ == "__main__":
    signal.signal(signal.SIGINT, killme)

    parser = optparse.OptionParser("usage: %prog [options]")
    parser.add_option("-k", "--key", dest = "api_key", type = "string", metavar="KEY", help = "Shodan API Key.")
    parser.add_option("-o", "--output", dest = "ofname", type = "string", metavar="FILE", help = "Write output to FILE.")
    parser.add_option("-q", "--query", dest = "query", type = "string", metavar="STRING", help = "String used to query Shodan.")
    parser.add_option("--host", dest = "host", type = "string", metavar="IP", help = "IP of host to lookup.")
    parser.add_option("-e", "--exploit", dest = "exploit", type = "string", metavar="STRING", help = "String used to query for exploits.")
    parser.add_option("-x", "--xml", dest = "xml_file", type = "string", metavar="FILE", help = "Name of XML file to import and perform operations on locally.")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help = "Verbose mode.")

    (options, args) = parser.parse_args()
    
    if not options.ofname:
        parser.error("Output file not specified.")
        parser.print_help()
    
    if not (options.query or options.host or options.exploit):
        parser.error("Not enough arguements given.")
        parser.print_help()
    
    if (options.host or options.exploit) and (not options.api_key or options.xml_file):
        parser.error("Exploit/Host lookups aren't locally supported and require a Shodan API Key.")
    
    if not options.xml_file and not options.api_key:
        parser.error("Shodan API key required to perform queries.")
    
    if options.api_key:
        api = WebAPI(options.api_key)

    if options.verbose:
        def verboseprint(*args):
            for arg in args:
               print arg,
            print
    else:
        verboseprint = lambda *a: None
    
    if options.xml_file and options.xml_file != "":
        tree = ET.parse(xml_file)
    
    out_tree = ET.ElementTree(ET.Element("shodan"))
    out_root = tree.getroot()
    
    if options.query:
        if options.xml_file:
            query(options.query,True)
        else:
            query(options.query)
    if options.host:
        lookupHost(options.host)
    if options.exploit:
        findExploits(options.exploit)
    
    fname = formatFilename(options.ofname)
    exportResults(tree,fname)
