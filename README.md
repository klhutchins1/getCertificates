# Scan domains for certificates and information about them


## Useage

#### Single Domain
`python3 getCertificates.py -s localhost`

#### Multidomain from file
`python3 getCertificates.py -f domains.txt`

#### Multidomain from file output to csv
`python3 getCertificates.py -f domains.txt -o domains.csv`

#### Domain file
The domain file should not include protocol information such as HTTPS
One domain perline
Ports are supported

## Help
```
-h, --help            show this help message and exit
  -f DOMAINFILE, --domainFile DOMAINFILE
                        This is the file with list of domains, one domain per line
  -s SINGLE, --single SINGLE
                        This is to query a single domain with it's info
  -o OUTPUT, --output OUTPUT
                        filename to save as.
```
