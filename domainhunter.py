#!/usr/bin/env python

## Title:       domainhunter.py
## Author:      Joe Vest and Andrew Chiles
## Description: Checks expired domains, bluecoat categorization, and Archive.org history to determine 
##              good candidates for phishing and C2 domain names

# To-do: 
# Add reputation categorizations to identify desireable vs undesireable domains
# Code cleanup/optimization
# Read in list of desired domain names
# Add Authenticated "Members-Only" option to download CSV/txt (https://member.expireddomains.net/domains/expiredcom/)

import time 
import random
import argparse
import json

## Functions

def checkBluecoat(domain):
    try:
        url = 'https://sitereview.bluecoat.com/rest/categorization'
        postData = {"url":domain}    # HTTP POST Parameters
        headers = {'User-Agent':useragent,
                    'X-Requested-With':'XMLHttpRequest',
                    'Referer':'https://sitereview.bluecoat.com/sitereview.jsp'}

        print('[*] BlueCoat Check: {}'.format(domain))
        response = s.post(url,headers=headers,data=postData,verify=False)

        responseJson = json.loads(response.text)

        if 'errorType' in responseJson:
            a = responseJson['errorType']
        else:
            soupA = BeautifulSoup(responseJson['categorization'], 'lxml')
            a = soupA.find("a").text

        return a
    except:
        print('[-] Error retrieving Bluecoat reputation!')
        return "-"

def checkIBMxForce(domain):
    try: 
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent':useragent,
                    'Accept':'application/json, text/plain, */*',
                    'x-ui':'XFE',
                    'Origin':url,
                    'Referer':url}

        print('[*] IBM xForce Check: {}'.format(domain))

        url = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
        response = s.get(url,headers=headers,verify=False)

        responseJson = json.loads(response.text)

        if 'error' in responseJson:
            a = responseJson['error']
        else:
            a = responseJson["result"]['cats']

        return a

    except:
        print('[-] Error retrieving IBM x-Force reputation!')
        return "-"

def downloadMalwareDomains():
    url = malwaredomains
    response = s.get(url,headers=headers,verify=False)
    responseText = response.text
    if response.status_code == 200:
        return responseText
    else:
        print("Error reaching:{}  Status: {}").format(url, response.status_code)

## MAIN
if __name__ == "__main__":

    try:
        import requests
        from bs4 import BeautifulSoup
        from texttable import Texttable
        
    except Exception as e:
        print "Expired Domains Reputation Check"
        print "[-] Missing dependencies: {}".format(str(e))
        print "[*] Install required dependencies by running `pip install -r requirements.txt`"
        quit(0)

    parser = argparse.ArgumentParser(description='Checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for C2 and phishing domains')
    parser.add_argument('-q','--query', help='Optional keyword used to refine search results', required=False, type=str)
    parser.add_argument('-c','--check', help='Perform slow reputation checks', required=False, default=False, action='store_true')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains (min. 100)', required=False, type=int, default=100)
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, type=int, default=400)
    parser.add_argument('-f','--file', help='Input file containing potential domain names to check (1 per line)', required=False, type=str)
    args = parser.parse_args()

## Variables
    query = False
    if args.query: 
        query = args.query

    check = args.check
    maxresults = args.maxresults
    
    if maxresults < 100:
        maxresults = 100

    maxwidth=args.maxwidth
    
    inputfile = False
    if args.file:
        inputfile = args.file

    t = Texttable(max_width=maxwidth)
    malwaredomains = 'http://mirror1.malwaredomains.com/files/justdomains'
    expireddomainsqueryurl = 'https://www.expireddomains.net/domain-name-search'
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
            
    useragent = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'
    headers = {'User-Agent':useragent}

    requests.packages.urllib3.disable_warnings()
 
    # HTTP Session container, used to manage cookies, session tokens and other session information
    s = requests.Session()

    data = []

    title = '''
 ____   ___  __  __    _    ___ _   _   _   _ _   _ _   _ _____ _____ ____  
|  _ \ / _ \|  \/  |  / \  |_ _| \ | | | | | | | | | \ | |_   _| ____|  _ \ 
| | | | | | | |\/| | / _ \  | ||  \| | | |_| | | | |  \| | | | |  _| | |_) |
| |_| | |_| | |  | |/ ___ \ | || |\  | |  _  | |_| | |\  | | | | |___|  _ < 
|____/ \___/|_|  |_/_/   \_\___|_| \_| |_| |_|\___/|_| \_| |_| |_____|_| \_\ '''

    print(title)
    print("")
    print("Expired Domains Reptutation Checker")
    print("")
    print("DISCLAIMER:")
    print("This is for educational purposes only!")
    disclaimer = '''It is designed to promote education and the improvement of computer/cyber security.  
The authors or employers are not liable for any illegal act or misuse performed by any user of this tool.
If you plan to use this content for illegal purpose, don't.  Have a nice day :)'''
    print(disclaimer)
    print("")
    print("********************************************")
    print("Start Time:             {}").format(timestamp)
    print("TextTable Column Width: {}").format(str(maxwidth))
    print("Checking Reputation:    {}").format(str(check))
    print("Number Domains Checked: {}").format(maxresults)
    print("********************************************")

    runtime = 0
    if check:
        runtime = (maxresults * 20) / 60

    else:
        runtime = maxresults * .15 / 60

    print("Estimated Max Run Time: {} minutes").format(int(runtime))
    print("")

    print('[*] Downloading malware domain list from {}'.format(malwaredomains))
    maldomains = downloadMalwareDomains()

    maldomains_list = maldomains.split("\n")

    # Use the keyword string to narrow domain search if provided
    # Need to modify this to pull more than the first 25 results
    if query:
        print('[*] Fetching expired or deleted domains containing "{}"...').format(query)
        
        for i in range (0,maxresults,25):
            if i == 0:
                url = "{}/?q={}".format(expireddomainsqueryurl,query)
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?q={}&searchinit=1'.format(query)
            else:
                url = "{}/?start={}&q={}".format(expireddomainsqueryurl,i,query)
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?start={}&q={}'.format((i-25),query)
            print("[*]  {}".format(url))
            
            # Annoyingly when querying specific keywords the expireddomains.net site requires additional cookies which 
            #  are set in JavaScript and not recognized by Requests so we add them here manually
            jar = requests.cookies.RequestsCookieJar()
            jar.set('_pk_id.10.dd0a', '*', domain='expireddomains.net', path='/')
            jar.set('_pk_ses.10.dd0a', '*', domain='expireddomains.net', path='/')
            
            domains = s.get(url,headers=headers,verify=False,cookies=jar).text

            # Turn the HTML into a Beautiful Soup object
            soup = BeautifulSoup(domains, 'lxml')
            table = soup.find("table")
            try:
                for row in table.findAll('tr')[1:]:

                    # Alternative way to extract domain name
                    # domain = row.find('td').find('a').text

                    cells = row.findAll("td")
                    if len(cells) >= 1:
                        output = ""
                        c0 = row.find('td').find('a').text   # domain
                        c1 = cells[1].find(text=True)   # bl
                        c2 = cells[2].find(text=True)   # domainpop
                        c3 = cells[3].find(text=True)   # birth
                        c4 = cells[4].find(text=True)   # entries
                        c5 = cells[5].find(text=True)   # similarweb
                        c6 = cells[6].find(text=True)   # similarweb country code
                        c7 = cells[7].find(text=True)   # moz
                        c8 = cells[8].find(text=True)   # status com
                        c9 = cells[9].find(text=True)   # status net
                        c10 = cells[10].find(text=True) # status org
                        c11 = cells[11].find(text=True) # status de
                        c12 = cells[12].find(text=True) # tld registered
                        c13 = cells[13].find(text=True) # monthly searches
                        c14 = cells[14].find(text=True) # adwords competition
                        c15 = cells[15].find(text=True) # list
                        c16 = cells[16].find(text=True) # status
                        c17 = cells[17].find(text=True) # related links

                        available = ''
                        if c8 == "available":
                            available += ".com "

                        if c9 == "available":
                            available += ".net "

                        if c10 == "available":
                            available += ".org "

                        if c11 == "available":
                            available += ".de "

                        # Skip additional reputation checks if this domain is already categorized as malicious 
                        if c0 in maldomains_list:
                            print("[-] Skipping {} - Identified as known malware domain").format(c0)
                        else:
                            bluecoat = ''
                            ibmxforce = ''
                            if c3 == '-':
                                bluecoat = 'ignored'
                                ibmxforce = 'ignored'
                            elif check == True:
                                bluecoat = checkBluecoat(c0)
                                print "[+] {} is categorized as: {}".format(c0, bluecoat)
                                ibmxforce = checkIBMxForce(c0)
                                print "[+] {} is categorized as: {}".format(c0, ibmxforce)
                                # Sleep to avoid captchas
                                time.sleep(random.randrange(10,20))
                            else:
                                bluecoat = "skipped"
                                ibmxforce = "skipped"
                            # Append parsed domain data to list
                            data.append([c0,c3,c4,available,bluecoat,ibmxforce])
            except: 
                print "[-] Error: No results found on this page!"

    # Retrieve the most recent expired/deleted domain results
    elif inputfile:

        print('[*] Fetching domain reputation from file: {}').format(inputfile)
        # read in file contents to list
        try:
            domains = [line.rstrip('\r\n') for line in open(inputfile, "r")]
            
        except IOError:
            print '[-] Error: {} does not appear to exist.'.format(inputfile)
            exit()
        
        print('[*] Domains loaded: {}').format(len(domains))
        for domain in domains:
            if domain in maldomains_list:
                print("[-] Skipping {} - Identified as known malware domain").format(domain)
            else:
                bluecoat = ''
                ibmxforce = ''
                bluecoat = checkBluecoat(domain)
                print "[+] {} is categorized as: {}".format(domain, bluecoat)
                ibmxforce = checkIBMxForce(domain)
                print "[+] {} is categorized as: {}".format(domain, ibmxforce)
                # Sleep to avoid captchas
                time.sleep(random.randrange(10,20))
                data.append([domain,'-','-','-',bluecoat,ibmxforce])

    else:

        print('[*] Fetching {} expired or deleted domains...').format(query)
        
        # Generate list of URLs to query for expired/deleted domains, queries return 25 results per page
        urls = []

        for i in range (0,(maxresults/4),25):
            urls.append('https://www.expireddomains.net/backorder-expired-domains?start={}'.format(i))
            urls.append('https://www.expireddomains.net/deleted-com-domains/?start={}o=changes&r=d'.format(i))
            urls.append('https://www.expireddomains.net/deleted-net-domains/?start={}o=changes&r=d'.format(i))
            urls.append('https://www.expireddomains.net/deleted-org-domains/?start={}o=changes&r=d'.format(i))

        for url in urls:

            print("[*]  {}".format(url))
            expireddomains = s.get(url,headers=headers,verify=False).text

            # Turn the HTML into a Beautiful Soup object
            soup = BeautifulSoup(expireddomains, 'lxml')
            table = soup.find("table")

        try:
            for row in table.findAll('tr')[1:]:

                cells = row.findAll("td")
                if len(cells) >= 1:
                    output = ""
                    c0 = cells[0].find(text=True)   # domain
                    c1 = cells[1].find(text=True)   # bl
                    c2 = cells[2].find(text=True)   # domainpop
                    c3 = cells[3].find(text=True)   # birth
                    c4 = cells[4].find(text=True)   # entries
                    c5 = cells[5].find(text=True)   # similarweb
                    c6 = cells[6].find(text=True)   # similarweb country code
                    c7 = cells[7].find(text=True)   # moz
                    c8 = cells[8].find(text=True)   # status com
                    c9 = cells[9].find(text=True)   # status net
                    c10 = cells[10].find(text=True) # status org
                    c11 = cells[11].find(text=True) # status de
                    c12 = cells[12].find(text=True) # tld registered
                    c13 = cells[13].find(text=True) # changes
                    c14 = cells[14].find(text=True) # whois
                    # Expired Domains results have an additional 'Availability' column that breaks parsing "deleted" domains
                    #c15 = cells[15].find(text=True) # related links

                    available = ''
                    if c8 == "available":
                        available += ".com "

                    if c9 == "available":
                        available += ".net "

                    if c10 == "available":
                        available += ".org "

                    if c11 == "available":
                        available += ".de "

                    # Skip additional reputation checks if this domain is already categorized as malicious 
                    if c0 in maldomains_list:
                        print("[-] Skipping {} - Identified as known malware domain").format(c0)
                    else:
                        bluecoat = ''
                        ibmxforce = ''
                        if c3 == '-':
                            bluecoat = 'ignored'
                            ibmxforce = 'ignored'
                        elif check == True:
                            bluecoat = checkBluecoat(c0)
                            print "[+] {} is categorized as: {}".format(c0, bluecoat)
                            ibmxforce = checkIBMxForce(c0)
                            print "[+] {} is categorized as: {}".format(c0, ibmxforce)
                            # Sleep to avoid captchas
                            time.sleep(random.randrange(10,20))
                        else:
                            bluecoat = "skipped"
                            ibmxforce = "skipped"
                        # Append parsed domain data to list
                        data.append([c0,c3,c4,available,bluecoat,ibmxforce])
        except: 
            print "[-] Error: No results found on this page!"

    # Sort domain list by column 2 (Birth Year)
    sortedData = sorted(data, key=lambda x: x[1], reverse=True) 

    t.add_rows(sortedData)
    header = ['Domain', 'Birth', '#', 'TLDs', 'BC', 'IBM']
    t.header(header)

    # Build HTML Table
    html = ''
    htmlHeader = '<html><head><title>Expired Domain List</title></head>'
    htmlBody = '<body><p>The following available domains report was generated at {}</p>'.format(timestamp)
    htmlTableHeader = '''
                
                 <table border="1" align="center">
                    <th>Domain</th>
                    <th>Birth</th>
                    <th>Entries</th>
                    <th>TLDs Available</th>
                    <th>Bluecoat</th>
                    <th>Categorization</th>
                    <th>IBM-xForce</th>
                    <th>Categorization</th>
                    <th>WatchGuard</th>
                    <th>Namecheap</th>
                    <th>Archive.org</th>
                 '''

    htmlTableBody = ''
    htmlTableFooter = '</table>'
    htmlFooter = '</body></html>'

    # Build HTML table contents
    for i in sortedData:
        htmlTableBody += '<tr>'
        htmlTableBody += '<td>{}</td>'.format(i[0]) # Domain
        htmlTableBody += '<td>{}</td>'.format(i[1]) # Birth
        htmlTableBody += '<td>{}</td>'.format(i[2]) # Entries
        htmlTableBody += '<td>{}</td>'.format(i[3]) # TLDs
        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/sitereview.jsp#/?search={}" target="_blank">Bluecoat</a></td>'.format(i[0]) # Bluecoat
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Bluecoat Categorization
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">IBM-xForce</a></td>'.format(i[0]) # IBM xForce
        htmlTableBody += '<td>{}</td>'.format(i[5]) # IBM x-Force Categorization
        htmlTableBody += '<td><a href="http://www.borderware.com/domain_lookup.php?ip={}" target="_blank">WatchGuard</a></td>'.format(i[0]) # Borderware WatchGuard
        htmlTableBody += '<td><a href="https://www.namecheap.com/domains/registration/results.aspx?domain={}" target="_blank">Namecheap</a></td>'.format(i[0]) # Namecheap
        htmlTableBody += '<td><a href="http://web.archive.org/web/*/{}" target="_blank">Archive.org</a></td>'.format(i[0]) # Archive.org
        htmlTableBody += '</tr>'

    html = htmlHeader + htmlBody + htmlTableHeader + htmlTableBody + htmlTableFooter + htmlFooter

    logfilename = "{}_domainreport.html".format(timestamp)
    log = open(logfilename,'w')
    log.write(html)
    log.close

    print("\n[*] Search complete")
    print("[*] Log written to {}\n").format(logfilename)


    print(t.draw())


