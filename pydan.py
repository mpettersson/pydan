import optparse
import signal
from shodan import WebAPI
import xml.etree.ElementTree as ET

SHODAN_API_KEY = ":)"

#exit handler for signals.
def killme(signum = 0, frame = 0):
    os.kill(os.getpid(), 9)


api = WebAPI(SHODAN_API_KEY)

def queryShodan():
    while True:
        query = raw_input("Please enter your query: ")
        if query != "":
            break
    
    print "Searching Shodan...",
    try:
        results = api.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    dictToXMLTree(results)

def lookupHost():
    while True:
        ip = raw_input("Please enter an IP: ")
        if ip != "":
            break
    
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

def findExploits():
    while True:
        query = raw_input("Please enter your query: ")
        if query != "":
            break
    
    print "Searching for exploits...",
    try:
        exploits = api.exploits.search(query)
    except Exception, e:
        print "Failed! (Error: %s)" % e
    
    print "Success!"
    return exploits

def exitProgram():
    while True:
        ans = raw_input("Are you sure you want to exit [Y/n]? ")
        ans = ans.lower()
        
        if ans == "y" or ans == "":
            exit(0)
        if ans == "n":
            return

def formatFilename(fname):
    valid_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    filename = ''.join(c for c in fname if c in valid_chars)
    filename = filename.replace(' ','_')
    if not filename.endswith(".xml"):
        filename += ".xml"
    return filename

def exportResults(tree):
    while True:
        fname = raw_input("Please enter a file name: ")
        if fname != "":
            break
    fname = formatFilename(fname)
    tree.write(fname)

def dictToXMLTree(dict):
    global root
    for host in dict['matches']:
        root.append(ET.Element("host",host))

if __name__ == "__main__":
    signal.signal(signal.SIGINT, killme)

    parser = optparse.OptionParser("usage: %prog [options]")
    parser.add_option("-x", "--xml", dest = "xml_file", type = "string", help = "Name of XML file to import.")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help = "Verbose mode.")

    (options, args) = parser.parse_args()

    if options.verbose:
        def verboseprint(*args):
            for arg in args:
               print arg,
            print
    else:
        verboseprint = lambda *a: None
    
    if options.xml_file and options.xml_file != "":
        tree = ET.parse(xml_file)
    else:
        tree = ET.ElementTree(ET.Element("shodan"))
    root = tree.getroot()
    
    while True:
        print """
        1) Query Shodan
        2) Lookup information about a host on Shodan
        3) Search for exploits
        4) Export results
        5) Quit
        """
        choice = raw_input("What would you like to do? ")
        
        if choice == "1":
            queryShodan()
        elif choice == "2":
            lookupHost()
        elif choice == "3":
            findExploits()
        elif choice == "4":
            exportResults()
        elif choice == "5":
            exitProgram()