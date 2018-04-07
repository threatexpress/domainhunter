#!/usr/bin/env python

## Title:       domainhunter.py
## Author:      @joevest and @andrewchiles
## Description: Checks expired domains, reputation/categorization, and Archive.org history to determine 
##              good candidates for phishing and C2 domain names

# To-do:
# Add reputation categorizations to identify desireable vs undesireable domains
# Code cleanup/optimization
# Add Authenticated "Members-Only" option to download CSV/txt (https://member.expireddomains.net/domains/expiredcom/)

import time 
import random
import argparse
import json

__version__ = "20180407"

## Functions

def checkBluecoat(domain):
    try:
        url = 'https://sitereview.bluecoat.com/resource/lookup'
        postData = {'url':domain,'captcha':''}   # HTTP POST Parameters
        headers = {'User-Agent':useragent,
                    'Content-Type':'application/json; charset=UTF-8',
                    'Referer':'https://sitereview.bluecoat.com/lookup'}

        print('[*] BlueCoat Check: {}'.format(domain))
        response = s.post(url,headers=headers,json=postData,verify=False)

        responseJSON = json.loads(response.text)

        if 'errorType' in responseJSON:
            a = responseJSON['errorType']
        else:
            a = responseJSON['categorization'][0]['name']
        
        # # Print notice if CAPTCHAs are blocking accurate results
        # if a == 'captcha':
        #     print('[-] Error: Blue Coat CAPTCHA received. Change your IP or manually solve a CAPTCHA at "https://sitereview.bluecoat.com/sitereview.jsp"')
        #     #raw_input('[*] Press Enter to continue...')

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

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = responseJSON['error']
        else:
            a = str(responseJSON["result"]['cats'])

        return a

    except:
        print('[-] Error retrieving IBM x-Force reputation!')
        return "-"

def checkTalos(domain):
    try:
        url = "https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={0}&offset=0&order=ip+asc".format(domain)
        headers = {'User-Agent':useragent,
                   'Referer':url}

        print('[*] Cisco Talos Check: {}'.format(domain))
        response = s.get(url,headers=headers,verify=False)
        
        responseJSON = json.loads(response.text)
        if 'error' in responseJSON:
            a = str(responseJSON['error'])
        else:
            a = '{0} (Score: {1})'.format(str(responseJSON['category']['description']), str(responseJSON['web_score_name']))
       
        return a

    except:
        print('[-] Error retrieving Talos reputation!')
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
        print("Expired Domains Reputation Check")
        print("[-] Missing dependencies: {}".format(str(e)))
        print("[*] Install required dependencies by running `pip install -r requirements.txt`")
        quit(0)

    parser = argparse.ArgumentParser(description='Finds expired domains, domain categorization, and Archive.org history to determine good candidates for C2 and phishing domains')
    parser.add_argument('-q','--query', help='Optional keyword used to refine search results', required=False, default=False, type=str, dest='query')
    parser.add_argument('-c','--check', help='Perform slow reputation checks', required=False, default=False, action='store_true', dest='check')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains (min. 100)', required=False, default=100, type=int, dest='maxresults')
    parser.add_argument('-s','--single', help='Performs reputation checks against a single domain name.', required=False, default=False, dest='single')
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, default=400, type=int, dest='maxwidth')
    parser.add_argument('-v','--version', action='version',version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args()

## Variables

    query = args.query

    check = args.check
    
    maxresults = args.maxresults
    
    if maxresults < 100:
        maxresults = 100
    
    single = args.single

    maxwidth = args.maxwidth
    
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
    print("Expired Domains Reputation Checker")
    print("Authors: @joevest and @andrewchiles\n")
    print("DISCLAIMER: This is for educational purposes only!")
    disclaimer = '''It is designed to promote education and the improvement of computer/cyber security.  
The authors or employers are not liable for any illegal act or misuse performed by any user of this tool.
If you plan to use this content for illegal purpose, don't.  Have a nice day :)'''
    print(disclaimer)
    print("")

    # Retrieve reputation for a single choosen domain (Quick Mode)
    if single:
        domain = single
        print('[*] Fetching domain reputation for: {}'.format(domain))

        bluecoat = ''
        ibmxforce = ''
        ciscotalos = ''
        
        bluecoat = checkBluecoat(domain)
        print("[+] {}: {}".format(domain, bluecoat))
        
        ibmxforce = checkIBMxForce(domain)
        print("[+] {}: {}".format(domain, ibmxforce))

        ciscotalos = checkTalos(domain)
        print("[+] {}: {}".format(domain, ciscotalos))

        quit()

    # Calculate estimated runtime based on sleep variable
    runtime = 0
    if check:
        runtime = (maxresults * 20) / 60

    else:
        runtime = maxresults * .15 / 60

    print("Estimated Max Run Time: {} minutes\n".format(int(runtime)))
    
    # Download known malware domains
    print('[*] Downloading malware domain list from {}'.format(malwaredomains))
    maldomains = downloadMalwareDomains()

    maldomains_list = maldomains.split("\n")
      
    # Generic Proxy support 
    # TODO: add as a parameter 
    proxies = {
      'http': 'http://127.0.0.1:8080',
      'https': 'http://127.0.0.1:8080',
    }

    # Create an initial session
    domainrequest = s.get("https://www.expireddomains.net",headers=headers,verify=False)
    #domainrequest = s.get("https://www.expireddomains.net",headers=headers,verify=False,proxies=proxies)

    # Generate list of URLs to query for expired/deleted domains, queries return 25 results per page
    urls = []

    # Use the keyword string to narrow domain search if provided
    if query:

        print('[*] Fetching expired or deleted domains containing "{}"'.format(query))
        for i in range (0,maxresults,25):
            if i == 0:
                urls.append("{}/?q={}".format(expireddomainsqueryurl,query))
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?q={}&start=1'.format(query)
            else:
                urls.append("{}/?start={}&q={}".format(expireddomainsqueryurl,i,query))
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?start={}&q={}'.format((i-25),query)
    
    # If no keyword provided, retrieve list of recently expired domains
    else:

        print('[*] Fetching expired or deleted domains...')
        for i in range (0,(maxresults),25):
            urls.append('https://www.expireddomains.net/backorder-expired-domains?start={}&o=changed&r=a'.format(i))
            urls.append('https://www.expireddomains.net/deleted-com-domains/?start={}&o=changed&r=a'.format(i))
            urls.append('https://www.expireddomains.net/deleted-net-domains/?start={}&o=changed&r=a'.format(i))
            urls.append('https://www.expireddomains.net/deleted-org-domains/?start={}&o=changed&r=a'.format(i))
    
    for url in urls:

        print("[*]  {}".format(url))

        # Annoyingly when querying specific keywords the expireddomains.net site requires additional cookies which 
        #  are set in JavaScript and not recognized by Requests so we add them here manually.
        # May not be needed, but the _pk_id.10.dd0a cookie only requires a single . to be successful
        # In order to somewhat match a real cookie, but still be different, random integers are introduced

        r1 = random.randint(100000,999999)


        # Known good example _pk_id.10.dd0a cookie: 5abbbc772cbacfb1.1496760705.2.1496760705.1496760705
        pk_str = '5abbbc772cbacfb1' + '.1496' + str(r1) + '.2.1496' + str(r1) + '.1496' + str(r1)

        jar = requests.cookies.RequestsCookieJar()
        jar.set('_pk_ses.10.dd0a', '*', domain='expireddomains.net', path='/')
        jar.set('_pk_id.10.dd0a', pk_str, domain='expireddomains.net', path='/')
        
        domainrequest = s.get(url,headers=headers,verify=False,cookies=jar)
        #domainrequest = s.get(url,headers=headers,verify=False,cookies=jar,proxies=proxies)

        domains = domainrequest.text

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

                    if query:

                        c0 = row.find('td').find('a').text   # domain
                        c1 = cells[1].find(text=True)   # bl
                        c2 = cells[2].find(text=True)   # domainpop
                        c3 = cells[3].find(text=True)   # birth
                        c4 = cells[4].find(text=True)   # Archive.org entries
                        c5 = cells[5].find(text=True)   # similarweb
                        c6 = cells[6].find(text=True)   # similarweb country code
                        c7 = cells[7].find(text=True)   # Dmoz.org
                        c8 = cells[8].find(text=True)   # status com
                        c9 = cells[9].find(text=True)   # status net
                        c10 = cells[10].find(text=True) # status org
                        c11 = cells[11].find(text=True) # status de
                        c12 = cells[12].find(text=True) # tld registered
                        c13 = cells[13].find(text=True) # Related Domains
                        c14 = cells[14].find(text=True) # Domain list
                        c15 = cells[15].find(text=True) # status
                        c16 = cells[16].find(text=True) # related links

                    else:
                        c0 = cells[0].find(text=True)   # domain
                        c1 = cells[1].find(text=True)   # bl
                        c2 = cells[2].find(text=True)   # domainpop
                        c3 = cells[3].find(text=True)   # birth
                        c4 = cells[4].find(text=True)   # Archive.org entries
                        c5 = cells[5].find(text=True)   # similarweb
                        c6 = cells[6].find(text=True)   # similarweb country code
                        c7 = cells[7].find(text=True)   # Dmoz.org
                        c8 = cells[8].find(text=True)   # status com
                        c9 = cells[9].find(text=True)   # status net
                        c10 = cells[10].find(text=True) # status org
                        c11 = cells[11].find(text=True) # status de
                        c12 = cells[12].find(text=True) # tld registered
                        c13 = cells[13].find(text=True) # changes
                        c14 = cells[14].find(text=True) # whois
                        c15 = ""                        # not used
                        c16 = ""                        # not used
                        c17 = ""                        # not used

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

                    status = ""
                    if c15:
                        status = c15

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
                            print("[+] {}: {}".format(c0, bluecoat))
                            ibmxforce = checkIBMxForce(c0)
                            print("[+] {}: {}".format(c0, ibmxforce))
                            # Sleep to avoid captchas
                            time.sleep(random.randrange(10,20))
                        else:
                            bluecoat = "skipped"
                            ibmxforce = "skipped"
                        # Append parsed domain data to list
                        data.append([c0,c3,c4,available,status,bluecoat,ibmxforce])
        except Exception as e: 
            print(e) 
            
    # Sort domain list by column 2 (Birth Year)
    sortedData = sorted(data, key=lambda x: x[1], reverse=True) 

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
                    <th>Status</th>
                    <th>Symantec</th>
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
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Status

        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/sitereview#/?search={}" target="_blank">Bluecoat</a></td>'.format(i[0]) # Bluecoat
        htmlTableBody += '<td>{}</td>'.format(i[5]) # Bluecoat Categorization
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">IBM-xForce</a></td>'.format(i[0]) # IBM xForce
        htmlTableBody += '<td>{}</td>'.format(i[6]) # IBM x-Force Categorization
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
    print("[*] Log written to {}\n".format(logfilename))
    
    # Print Text Table
    t = Texttable(max_width=maxwidth)
    t.add_rows(sortedData)
    header = ['Domain', 'Birth', '#', 'TLDs', 'Status', 'Symantec', 'IBM']
    t.header(header)
    print(t.draw())


