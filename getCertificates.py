from dataclasses import replace
from pickle import TRUE
from urllib.parse import urlparse
from os.path import exists
from socket import AF_INET, SOCK_DGRAM
from urllib3.exceptions import InsecureRequestWarning
import argparse
import ssl
import OpenSSL
import socket
import ipaddress
import csv
import logging
import requests


logging.basicConfig(filename='DEBUG.log', encoding='utf-8', level=logging.DEBUG)
certificate_data=[]


#https://stackoverflow.com/a/50894566
#return san from x509 certificate
def getCertificateSan(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san


#get IP addresses from DNS
#returns a list of IP addresses
def getIPAddress(address,port=443):
    IPlist = []
    hostnameIP = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)

    #extract IP info from list that looks like
    #[(<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('172.20.5.13', 443))]
    if len(hostnameIP) ==1:
        IPlist = hostnameIP[0][4][0]
    else:
        IPlist=[]
        for i in range(len(hostnameIP)):
            IPAddress = hostnameIP[i][4][0]
            IPlist.append(IPAddress)
        IPlist=",".join(str(x) for x in IPlist)
    logging.debug(f'IPlist')     
    return IPlist


#Grabs Certificate info from certificate and appends to global array certificate_data
def checkCertificate(address,port=443):
    global certificate_data

    cert = ssl.get_server_certificate((address, port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    x509notAfter = x509.get_notAfter()
    x509serial = x509.get_serial_number()
    x509fingerprint = x509.digest("sha1")
    if getCertificateSan(x509) :
        x509SAN = getCertificateSan(x509)
    else:
        x509SAN = "N/A"

    exp_day = x509notAfter[6:8].decode('utf-8')
    exp_month = x509notAfter[4:6].decode('utf-8')
    exp_year = x509notAfter[:4].decode('utf-8')
    serialNumber = '{0:x}'.format(x509serial)
    thumbprint = x509fingerprint.decode('utf-8').replace(':','')
    ipA = getIPAddress(address,port)
    exp_date = str(exp_month) + "-" + str(exp_day) + "-" + str(exp_year)

    print("SSL Certificate for",  address)
    print("IP address =",  ipA)
    print("Expires on (MM-DD-YYYY):", exp_date)
    print("serial# =", serialNumber)
    print("Thumbprint =", thumbprint)
    print("SAN =", x509SAN)

    certificate_data.append([address,ipA,exp_date,serialNumber,thumbprint,x509SAN])


#Takes filename inputed from user and writes it to CSV
def writeToCsv(output):
    # csv header
    header = ['Hostname', 'IP Address', 'Expiration Date', 'Serial Number', 'Thumbprint (SHA1)', 'SAN']

    with open(output, 'w', encoding='UTF8', newline='\n') as f:
        write = csv.writer(f)
        write.writerow(header)
        for i, value in enumerate(certificate_data):
            write.writerow(value)
        f.close()


#checks if string is IPv4... Not needed currently
def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        logging.debug("Domain string is an IP address " f'{string}')
        return True
    except ValueError:
        logging.debug("Domain string is NOT an IP address " f'{string}')
        return False


#with address and port, checks if site is up with requests
#TODO try to find if site is down or has something crazy with the non-standard responses
def is_siteUp(address,port=443):
    logging.debug("Trying to connect to " f'{address}' " on " f'{port}')
    # Suppress only the single warning from urllib3 needed.
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    if port == 443:
        url = "https://"+address
    else:
        url = "https://"+address+":"+port
    try:
		#Get Url but don't care about the validity of Certificate
        get = requests.get(url, verify=False, timeout=2)
        if get.status_code == 200:
            logging.info(f"{address}: is UP")
            return True
        elif get.status_code == 404:
            logging.info(f"{address}: is 404, status_code: {get.status_code}")
            return False
        else:
            logging.info(f"{address}: has something wrong with it")
            return True
    #Exception
    except requests.ConnectionError as e:
        print("Connection Error to f{address}. Make sure you are connected to Internet.")
        logging.info(f"{address}: is NOT reachable")  
        print(f"{address}: is NOT reachable \nErr: {e}")
        print(str(e))
    except requests.Timeout as e:
        print("Timeout Error")
        print(str(e))
    except requests.RequestException as e:
        print("General Error")
        print(str(e))
    except KeyboardInterrupt:
        print("Someone closed the program")



#This needs to be cleaned up itself
#Takes the line and finds if there is a port 
def cleanInputDomains(line):
    #TODO use urlparse to grab domain info and not the below elif
    #TODO clean up http and other protocols
    #TODO validate port is INT 
    #TODO ensure string is not dangerous
    domain = urlparse(line).path
    logging.debug(f'{line}' " is being cleaned up")

    if line == '':
        print(line, " is not valid, don't have an empty line")
        logging.error(f'{line}' "is empty")
    elif '//' in line:
        print(line, " is not valid, please remove http:// and such")
        logging.error("URLparse does not like the domain " f'{line}' " and should be removed")
    elif ':' in line:
        logging.debug("The Domain " f'{line}' " has a port")
        portLoc = line.find(':')
        port = line[portLoc+1::]
        domain = line[:portLoc]
        #print("has Port")
        if is_siteUp(domain,port):
            checkCertificate(domain,port)
        else:
            print("site", line, "is down")
            logging.error(f'{line}' " is down")
            certificate_data.append([line,'NA','NA','NA','NA','NA'])
    #Port is not included in the line.. Assume port 443        
    else:
        print(domain)
        if is_siteUp(domain):
            checkCertificate(domain)
        else:
            print("site is down")
            certificate_data.append([line,'NA','NA','NA','NA','NA'])
        
#define arguments for script.
def argsetup():
    about  = 'Query a domain for it\'s certificate and get serial, Thumbprint, SANS, expiration'
    parser = argparse.ArgumentParser(description=about)
    parser.add_argument('-f','--domainFile',type=str,help='This is the file with list of domains, one domain per line')
    parser.add_argument('-s','--single',type=str,help='This is to query a single domain with it\'s info')
    parser.add_argument('-o','--output',type=str,help='filename to save as')
    args = parser.parse_args()
    return args


#Start of script
if __name__ == "__main__":
    args  = argsetup()
    file = args.domainFile
    domain = args.single
    output = args.output
    logging.debug("---- Script Starting ---")
    if file:
        logging.debug("reading from file with list of domains " f'{file}')
        with open(file) as rb:
            lines = rb.readlines()
            for line in lines:
                cleanInputDomains(line.strip())

    elif domain:
        logging.debug("Checking single domain " f'{domain}')
        cleanInputDomains(domain)

    else:
        logging.debug("Argument needed, either -f or -s ")
        print("include either -f for file of domains to check or -s for single domain")
        #TODO default print help or replace with argh package
    
    if output:
        #TODO make this a new function to check if file already exists.
        #TODO Output to file after each certificate check
        #TODO Fix Overwriting file
        file_exists = exists(output)
        if file_exists:
            logging.info("A file with the same name already exists " f'{output}')
            print("file already exists")
            replaceFile = input("would you like to replace? Y/N: ").upper()
            if replaceFile == 'Y':
                logging.info("User Selected to overwrite " f'{output}')
                writeToCsv(output)
            elif replaceFile == 'N':
                logging.info("User Selected to NOT to overwrite, need a new filename")
                output = input("Enter a new file name: ")
                writeToCsv(output)
            else:
                exit()

        else:
            writeToCsv(output)
        
        
    print(certificate_data)