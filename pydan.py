import os
import re
import signal
import argparse
from shodan import WebAPI
import xml.etree.ElementTree as ET
from collections import defaultdict

class CustomArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super(CustomArgumentParser, self).__init__(*args, **kwargs)

    def convert_arg_line_to_args(self, line):
        for arg in line.split():
            if not arg.strip():
                continue
            if arg[0] == '#':
                break
            yield arg

#TODO: Predefined queries?
#TODO: Logic to correlate exploits to hosts/devices?

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)

def query(query, local=False):
    if local:
        verboseprint("performing a local query (\"",query,"\")")
        
        filters = re.findall("\w:\w",query)
        if filters:
            filter = []
            for i in filters:
                query.replace(i, "")
                parts = i.split(":")
                filter.append(parts[0]+"=\""+parts[1]+"\"")
            #ElementTree doesn't have full XPath support
            #(left in below code in case of upgrade to lxml)
            # filter = "["
            # for i in filters:
                # parts = i.split(":")
                # filter += "@"+parts[0]+"='"+parts[1]+"' or "
            # filter = filter[:-4]+"]"
        
        query = query.strip()
        phrases = []
        exacts = re.findall('".+"',q)
        if exacts:
            for i in exacts:
                query.replace(i, "")
                phrases.append(i.replace('"',""))
        
        for word in query.strip().split():
            phrases.append(word)
        
        global out_tree
        out_imported_query_hosts = out_tree.find("./imported_query/hosts")
        out_query = ET.SubElement(out_tree,"query",{"query":query,"type":"local"})
        out_hosts = ET.SubElement(out_query,"hosts")
        
        for host in out_imported_query_hosts:
            if any(word in host.attrib.itervalues() for word in filter):
                if any(phrase in host[0].text for phrase in phrases):
                    out_hosts.append(ET.Element("host",host))
    else:
        print "Searching Shodan...",
        try:
            verboseprint("submitting query to Shodan via webapi (\"",query,"\")")
            results = api.search(query)
        except Exception, e:
            print "Failed! (Error: %s)" % e
        
        print "Success!"
        
        verboseprint("importing query results to XML tree")
        global out_tree
        out_query = ET.SubElement(out_tree,"query",{"query":query,"type":"api"})
        out_hosts = ET.SubElement(out_query,"hosts")#add metdata to attrib?
        for host in results["matches"]:
            out_hosts.append(ET.Element("host",host))

def lookupHost(ip):
    print "Looking up host on Shodan...",
    try:
        verboseprint("sumitting host (",ip,") query to Shodan via webapi")
        host = api.host(ip)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    
    verboseprint("""
        IP: %s
        Country: %s
        City: %s
    """ % (host['ip'], host.get("country", None), host.get("city", None)))

    for item in host['data']:
        verboseprint("""
                Port: %s
                Banner: %s

        """ % (item["port"], item["banner"]))
    
    verboseprint("importing host info to XML tree")
    global out_tree
    out_query = ET.SubElement(out_tree,"host_query",{"query":ip})
    out_host = ET.SubElement(out_query,"host"})
    out_host.append(ET.Element("host",host))

def findExploits(query):
    print "Searching for exploits...",
    try:
        verboseprint("submitting exploit query to Shodan via webapi (\"",query,"\")")
        exploits = api.exploitdb.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    
    verboseprint("importing query results to XML tree")
    global out_tree
    out_query = ET.SubElement(out_tree,"exploit_query",{"query":query})
    out_exploits = ET.SubElement(out_query,"exploits"})
    for exploit in exploits["matches"]:
        out_exploits.append(ET.Element("exploit",exploit))

def formatFilename(fname):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = "".join(c for c in fname if c in valid_chars)
    filename = filename.replace(" ","_")
    if not filename.endswith(".xml"):
        filename += ".xml"
    verboseprint("formatted output filename \"",fname,"\" to \"",filename,"\"")
    return filename

def fingerprint(banner):
    try:
        matches = api.fingerprint(banner)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    return matches

def enumServers():
    global out_tree
    out_query = out_tree.find('./query')
    out_query_hosts = out_query.find('./hosts')
    regex_server = re.compile('Server: (.+)')
    serverSummary = defaultdict(list)
    
    for host in out_query_hosts:
        match = regex_server.search(host[0].text)
        if match:
            serverSummary[match.group(1)].append(host)
    
    out_servers = ET.SubElement(out_query,"servers")
    for server_type, hosts in serverSummary.iteritems():
        server = ET.Element(server_type)
        for host in hosts:
            server.append("host",host)
        out_servers.append(server)

def importXML(tree, out_tree):
    verboseprint("importing xml file")
    root = tree.getroot()
    out_query = ET.SubElement(out_tree,"imported_query",root[0].attrib)
    out_hosts = ET.SubElement(out_query,"hosts")
    
    for i in xrange(1,len(root)):
        out_hosts.append(ET.Element("host",root[i]))
    verboseprint("imported xml file successfully")

def exportResults(tree, fname):
    tree.write(fname, xml_declaration=True)
    print "Wrote output to \"",fname,"\" successfullly!"

if __name__ == "__main__":
    signal.signal(signal.SIGINT, killme)
    
    parser = CustomArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    fromfile_prefix_chars='@',
    description=\
'''
pydan is a tool that provides a way to easily use the Shodan API (using your 
own API key) and try to perform some analysis to find interesting and possibly 
vulnerable devices.

  @FILE\t\t\tname of file to read line seperated arguments from
''')
    #there has to be a better way to format this ^
    #this is why i'm not a web developer
    parser.add_argument("-k", "--key", dest = "api_key", metavar="KEY", help = "Shodan API Key.")
    parser.add_argument("-o", "--output", dest = "ofname", type = argparse.FileType('w'), metavar="FILE", help = "write output to FILE", required = True)
    parser.add_argument("-x", "--xml", dest = "xml_file", type = argparse.FileType('r'), metavar="FILE", help = "name of XML file to import and perform operations on locally")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help = "verbose mode")
    
    #TODO:Option for "batch" file of queries?
    #TODO:Make '-k' and '-x' mutually exclusive? Or combine results?
    
    group = parser.add_argument_group(title='Actions (mutually exclusive)')
    actions = group.add_mutually_exclusive_group(required=True)
    actions.add_argument("-q", "--query", dest = "query", metavar="STRING", help = "string used to query Shodan")
    actions.add_argument("--host", dest = "host", metavar="IP", help = "ip of host to lookup")
    actions.add_argument("-e", "--exploit", dest = "exploit", metavar="STRING", help = "string used to query for exploits")
    
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
        verboseprint("key detected")
        api = WebAPI(args.api_key)
        verboseprint("webapi object created successfully")
    
    out_root = ET.Element("pydan")
    out_tree = ET.ElementTree(out_root)   
    verboseprint("initialized empty xml tree for output")
    
    if args.xml_file and args.xml_file != "":
        verboseprint("input xml file detected")
        tree = ET.parse(xml_file)
        verboseprint("parsed xml file successfully")
        importXML(tree, out_tree)
        del tree
    
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
