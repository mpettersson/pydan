import os
import re
import signal
import string
import argparse
from shodan import WebAPI
import xml.etree.ElementTree as ET
from collections import defaultdict

#TODO: Apply good coding standards and implement some OOP

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

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)

#TODO:Check if xml elements already exist (for possible future upgrades)
def query(out_tree, query, local=False):
    out_root = out_tree.getroot()
    
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
        
        out_imported_query_hosts = out_tree.find("./imported_query/hosts")
        out_query = ET.SubElement(out_root,"query",{"query":query,"type":"local"})
        out_hosts = ET.SubElement(out_query,"hosts")
        
        for host in out_imported_query_hosts:
            attributes = list(key+"=\""+value+"\"" for (key,value) in host.attrib.items())
            if any(word in attributes for word in filter):
                if any(phrase in host[0].text for phrase in phrases):
                    out_hosts.append(host)
        
        return out_query
    else:
        print "Searching Shodan . . .",
        try:
            verboseprint("submitting query to Shodan via webapi (\"",query,"\")")
            results = api.search(query)
        except Exception, e:
            print "Failed! (Error: %s)" % e
        
        print "Done"
        
        verboseprint("importing query results to XML tree")
        out_query = ET.SubElement(out_root,"query",{"query":query,"type":"api"})
        out_hosts = ET.SubElement(out_query,"hosts")#retain query metdata to attrib?
        for host in results["matches"]:
            data = ET.Element("data")
            data.text = host["data"]
            del host["data"]
            for attrib,value in host.items():
                #needed b/c limitation in ET serialization
                if not value:
                    del host[attrib]
                elif type(value) is list:
                    host[attrib] = value[0]
                else:
                    host[attrib] = unicode(value)
            h = ET.Element("host",host)
            h.append(data)
            out_hosts.append(h)
        
        return out_query

def lookupHost(out_tree, ip):
    out_root = out_tree.getroot()
    print "Looking up host on Shodan . . .",
    try:
        verboseprint("sumitting host (",ip,") query to Shodan via webapi")
        host = api.host(ip)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Done"
    
    verboseprint("importing host info to XML tree")
    out_query = ET.SubElement(out_root,"host_query",{"query":ip})
    out_host = ET.SubElement(out_query,"hosts")
    #just taking most recent scan data
    #(data format in scans changes over time)
    index = len(host["data"])-1
    data = ET.Element("data")
    data.text = host["data"][index]["banner"]
    del host["data"][index]["banner"]
    for attrib,value in host["data"][index].items():
        #needed b/c limitation in ET serialization
        if not value:
            del host["data"][index][attrib]
        elif type(value) is list:
            host["data"][index][attrib] = value[0] 
        else:
            host["data"][index][attrib] = unicode(value)
    h = ET.Element("host",host["data"][index])
    h.append(data)
    out_host.append(h)
    
    return out_query

def findExploits(out_tree, query):
    #include other databses? (e.g. metasploit)
    out_root = out_tree.getroot()
    print "Searching for exploits . . .",
    try:
        verboseprint("submitting exploit query to Shodan via webapi (\"",query,"\")")
        exploits = api.exploitdb.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Done"
    
    verboseprint("importing query results to XML tree")
    out_query = ET.SubElement(out_root,"exploit_query",{"query":query})
    out_exploits = ET.SubElement(out_query,"exploits")
    for exploit in exploits["matches"]:
        for attrib,value in exploit.items():
            #needed b/c limitation in ET serialization
            if not value:
                del exploit[attrib]
            elif type(value) is list:
                exploit[attrib] = value[0] 
            else:
                exploit[attrib] = unicode(value)
        e = ET.Element("exploit",exploit)
        out_exploits.append(e)
    
    return out_query

def formatFilename(fname):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = "".join(c for c in fname if c in valid_chars)
    filename = filename.replace(" ","_")
    if not filename.endswith(".xml"):
        filename += ".xml"
    verboseprint("formatted output filename \"",fname,"\" to \"",filename,"\"")
    return filename

def fingerprint(out_query):
    out_query_hosts = out_query.find('./hosts')
    
    print "Attempting to fingerprint host(s) . . .",
    for host in out_query_hosts:
        try:
            verboseprint("submitting fingerprint request to Shodan via webapi")
            results = api.fingerprint(host[0].text)
        except Exception, e:
            print "Failed! (Error: %s)" % e
        
        if results["matches"]:
            fingerprints = ET.SubElement(host,"fingerprints")
            num_results = min(len(results["matches"]),5)
            for i in range(num_results):
                f = ET.Element("fingerprint",{"server_type":unicode(results["matches"][i][0]),
                                              "confidence":unicode(results["matches"][i][1])})
                fingerprints.append(f)
    print "Done"

def enumServers(out_query):
    out_query_hosts = out_query.find('./hosts')
    regex_server = re.compile('Server: (.+)')
    serverSummary = defaultdict(list)
    
    for host in out_query_hosts:
        match = regex_server.search(host[0].text)
        if match:
            m = match.group(1).strip()
            if m:
                serverSummary[m].append(host)
    
    out_servers = ET.SubElement(out_query,"servers")
    for server_type, hosts in serverSummary.iteritems():
        server = ET.SubElement(out_servers,"server_type",{"name":server_type})
        server_hosts = ET.SubElement(server,"hosts")
        for host in hosts:
            server_hosts.append(host)
    
    return out_servers

def lookupServerExploits(out_servers):
    print "Performing auto exploit lookup . . .",
    for server in out_servers:
        exploits = None
        try:
            verboseprint("submitting exploit query to Shodan via webapi (\"",query,"\")")
            exploits = api.exploitdb.search(server.get("name"))
        except Exception, e:
            print "Failed! (Error: %s)" % e
        if exploits and not exploits["error"] and exploits["total"] > 0:
            server_exploits = ET.SubElement(server,"exploits",{"query":exploits["query"],
                                                               "total":unicode(exploits["total"])})
            for exploit in exploits["matches"]:
                for attrib,value in exploit.items():
                    #needed b/c limitation in ET serialization
                    exploit[attrib] = unicode(value)
                e = ET.Element("exploit",exploit)
                server_exploits.append(e)
    print "Done"

def importXML(tree, out_tree):
    out_root = out_tree.getroot()
    verboseprint("importing xml file")
    root = tree.getroot()
    out_query = ET.SubElement(out_root,"imported_query",root[0].attrib)
    out_hosts = ET.SubElement(out_query,"hosts")
    
    for i in xrange(1,len(root)):
        h = ET.Element("host",root[i])
        out_hosts.append(h)
    verboseprint("imported xml file successfully")

def exportResults(tree, fname):
    tree.write(fname, xml_declaration=True)
    print "Wrote output to \""+fname+"\" successfullly!"

if __name__ == "__main__":
    signal.signal(signal.SIGINT, killme)
    
    parser = CustomArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    fromfile_prefix_chars="@",
    usage="%(prog)s [OPTION]... (-q STRING | --host IP | -e STRING) -o FILE",
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
    parser.add_argument("-o", "--output", dest = "ofname", metavar="FILE", help = "write output to FILE", required = True)
    parser.add_argument("-x", "--xml", dest = "xml_file", type = argparse.FileType('r'), metavar="FILE", help = "name of XML file to import and perform operations on locally")
    parser.add_argument("--fingerprint", action="store_true", dest="fingerprint", help = "(experimental) attempt to fingerprint devices based on their banner's")
    parser.add_argument("--xlookup", action="store_true", dest="xlookup", help = "attempt to find exploits on the types of devices found")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help = "verbose mode")
    
    #with '-k' and '-x', allow api query too and append results?
    
    group = parser.add_argument_group(title='Actions (mutually exclusive)')
    actions = group.add_mutually_exclusive_group(required=True)
    actions.add_argument("-q", "--query", dest = "query", metavar="STRING", help = "string used to query Shodan")
    actions.add_argument("--host", dest = "host", metavar="IP", help = "ip of host to lookup")
    actions.add_argument("-e", "--exploit", dest = "exploit", metavar="STRING", help = "string used to query for exploits")
    actions.add_argument("-f", "--file", dest = "in_file", type = argparse.FileType('r'), metavar="FILE", help = "file name of query list")
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
    
    if not (args.query or args.host or args.exploit or args.in_file):
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
            out_query = query(out_tree, args.query, True)
        else:
            out_query = query(out_tree, args.query)
        out_servers = enumServers(out_query)
        if args.fingerprint:
                pass#which hosts to fingerprint? All seems too much (depending on query)
        if args.xlookup:
            out_server_exploits = lookupServerExploits(out_servers)
    if args.host:
        out_query = lookupHost(out_tree, args.host)
        out_servers = enumServers(out_query)
        if args.xlookup:
            out_server_exploits = lookupServerExploits(out_servers)
        if args.fingerprint:
            fingerprint(out_query)
    if args.exploit:
        out_query = findExploits(out_tree, args.exploit)
    if args.in_file:
        for line in args.in_file:
            query(out_tree, line)
        
    
    fname = formatFilename(args.ofname)
    exportResults(out_tree,fname)
