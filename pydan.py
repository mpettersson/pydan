import os
import signal
import argparse
from shodan import WebAPI
import xml.etree.ElementTree as ET

#TODO: Predefined queries?

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)

def query(query, local=False):
    if local:
        verboseprint("performing a local query (\"",query,"\")")
        #TODO: Locally query XML data
    else:
        print "Searching Shodan...",
        try:
            verboseprint("submitting query to Shodan via webapi (\"",query,"\")")
            results = api.search(query)
        except Exception, e:
            print "Failed! (Error: %s)" % e
        
        print "Success!"
        dictToXMLTree(results)

def lookupHost(ip):
    print "Looking up host on Shodan...",
    try:
        verboseprint("sumitting host (",ip,") query to Shodan via webapi")
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
    #TODO:Merge results into XML tree (needs unified XML format)

def findExploits(query):
    print "Searching for exploits...",
    try:
        verboseprint("submitting exploit query to Shodan via webapi (\"",query,"\")")
        exploits = api.exploits.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    #TODO:Merge results into XML tree (needs unified XML format)

def formatFilename(fname):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = ''.join(c for c in fname if c in valid_chars)
    filename = filename.replace(' ','_')
    if not filename.endswith(".xml"):
        filename += ".xml"
    verboseprint("formatted output filename \"",fname,"\" to \"",filename,"\"")
    return filename

def exportResults(tree, fname):
    tree.write(fname)
    print "Wrote output to \"",fname,"\" successfullly!"

def dictToXMLTree(dict):
    verboseprint("importing query results to XML tree")
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
    #TODO:Option for "batch" file of queries?
    #TODO:Make '-k' and '-x' mutually exclusive? Or combine results?
    
    #TODO:Mutually exclusive group? Or support multiple queries per run? (depends on unified XML format)
    group = parser.add_argument_group('Actions')
    group.add_argument("-q", "--query", dest = "query", metavar="STRING", help = "String used to query Shodan.")
    group.add_argument("--host", dest = "host", metavar="IP", help = "IP of host to lookup.")
    group.add_argument("-e", "--exploit", dest = "exploit", metavar="STRING", help = "String used to query for exploits.")
    
    #TODO:Maybe a merge XMLs feature?

    args = parser.parse_args()
    
    if args.verbose:
        def verboseprint(*args):
            for arg in args:
               print arg,
            print
        verboseprint("verbose mode activated")
    else:
        verboseprint = lambda *a: None
    
    if not (args.query or args.host or args.exploit):
        parser.error("Not enough arguements given.")
    
    if (args.host or args.exploit) and (not args.api_key or args.xml_file):
        parser.error("Exploit/Host lookups aren't locally supported and require a Shodan API Key.")
    
    if not args.xml_file and not args.api_key:
        parser.error("Shodan API key required to perform queries.")
    
    if args.api_key:
        verboseprint("api key detected")
        api = WebAPI(args.api_key)
        verboseprint("webapi object created successfully")
    
    if args.xml_file and args.xml_file != "":
        verboseprint("input XML file detected")
        tree = ET.parse(xml_file)
        verboseprint("parsed xml file successfully")
    
    #TODO:Define a unified XML structure
    out_tree = ET.ElementTree(ET.Element("shodan"))
    out_root = tree.getroot()
    verboseprint("initialized empty xml tree for output")
    
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
