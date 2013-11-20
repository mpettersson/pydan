import argparse
import signal
from shodan import WebAPI
import xml.etree.ElementTree as ET

#TODO: Predefined queries?

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)

def query(query, local=False):
    if local:
        pass#TODO: Locally query XML data
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
    
    parser = argparse.ArgumentParser(description='pydan description')#TODO: describe pydan
    parser.add_argument("-k", "--key", dest = "api_key", metavar="KEY", help = "Shodan API Key.")
    parser.add_argument("-o", "--output", dest = "ofname", type = argparse.FileType('w'), metavar="FILE", help = "Write output to FILE.", required = True)
    parser.add_argument("-x", "--xml", dest = "xml_file", type = argparse.FileType('r'), metavar="FILE", help = "Name of XML file to import and perform operations on locally.")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help = "Verbose mode.")
    
    #TODO:Mutually exclusive group? Or support multiple queries per run? (depends on unified XML format)
    group = parser.add_argument_group('Actions')
    group.add_argument("-q", "--query", dest = "query", metavar="STRING", help = "String used to query Shodan.")
    group.add_argument("--host", dest = "host", metavar="IP", help = "IP of host to lookup.")
    group.add_argument("-e", "--exploit", dest = "exploit", metavar="STRING", help = "String used to query for exploits.")
    
    #TODO:Maybe a merge XMLs feature?

    args = parser.parse_args()
    
    if not (args.query or args.host or args.exploit):
        parser.error("Not enough arguements given.")
    
    if (args.host or args.exploit) and (not args.api_key or args.xml_file):
        parser.error("Exploit/Host lookups aren't locally supported and require a Shodan API Key.")
    
    if not args.xml_file and not args.api_key:
        parser.error("Shodan API key required to perform queries.")
    
    if args.api_key:
        api = WebAPI(args.api_key)

    if args.verbose:
        def verboseprint(*args):
            for arg in args:
               print arg,
            print
    else:
        verboseprint = lambda *a: None
    
    if args.xml_file and args.xml_file != "":
        tree = ET.parse(xml_file)
    
    #TODO:Define a unified XML structure
    out_tree = ET.ElementTree(ET.Element("shodan"))
    out_root = tree.getroot()
    
    if args.query:
        if args.xml_file:
            query(args.query,True)
        else:
            query(args.query)
    if args.host:
        lookupHost(args.host)
    if args.exploit:
        findExploits(args.exploit)
    
    fname = formatFilename(args.ofname)
    exportResults(out_tree,fname)
