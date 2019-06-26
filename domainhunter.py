#!/usr/bin/env python

## Title:       domainhunter.py
## Author:      @joevest and @andrewchiles
## Description: Checks expired domains, reputation/categorization, and Archive.org history to determine 
##              good candidates for phishing and C2 domain names

# If the expected response format from a provider changes, use the traceback module to get a full stack trace without removing try/catch blocks
#import traceback
#traceback.print_exc()

import time 
import random
import argparse
import json
import base64
import os
import csv

__version__ = "20190626"

## Functions

def doSleep(timing):
    if timing == 0:
        time.sleep(random.randrange(90,120))
    elif timing == 1:
        time.sleep(random.randrange(60,90))
    elif timing == 2:
        time.sleep(random.randrange(30,60))
    elif timing == 3:
        time.sleep(random.randrange(10,20))
    elif timing == 4:
        time.sleep(random.randrange(5,10))
    # There's no elif timing == 5 here because we don't want to sleep for -t 5


def checkBluecoat(domain, proxies):
    try:
        url = 'https://sitereview.bluecoat.com/resource/lookup'
        postData = {'url':domain,'captcha':''}
        headers = {'User-Agent':useragent,
                   'Accept':'application/json, text/plain, */*',
                   'Content-Type':'application/json; charset=UTF-8',
                   'Referer':'https://sitereview.bluecoat.com/lookup'}

        print('[*] BlueCoat: {}'.format(domain))
        if proxies:
            response = s.post(url,headers=headers,json=postData,proxies=proxies,verify=False)
        else:
            response = s.post(url,headers=headers,json=postData,verify=False)

        responseJSON = json.loads(response.text)
        
        if 'errorType' in responseJSON:
            a = responseJSON['errorType']
        else:
            a = responseJSON['categorization'][0]['name']
        
        # Print notice if CAPTCHAs are blocking accurate results and attempt to solve if --ocr
        if a == 'captcha':
            if ocr:
                # This request is also performed by a browser, but is not needed for our purposes
                #captcharequestURL = 'https://sitereview.bluecoat.com/resource/captcha-request'

                print('[*] Received CAPTCHA challenge!')
                captcha = solveCaptcha('https://sitereview.bluecoat.com/resource/captcha.jpg',s,proxies)
                
                if captcha:
                    b64captcha = base64.urlsafe_b64encode(captcha.encode('utf-8')).decode('utf-8')
                   
                    # Send CAPTCHA solution via GET since inclusion with the domain categorization request doens't work anymore
                    captchasolutionURL = 'https://sitereview.bluecoat.com/resource/captcha-request/{0}'.format(b64captcha)
                    print('[*] Submiting CAPTCHA at {0}'.format(captchasolutionURL))
                    if proxies:
                        response = s.get(url=captchasolutionURL,headers=headers,verify=False,proxies=proxies)
                    else:
                        response = s.get(url=captchasolutionURL,headers=headers,verify=False)

                    # Try the categorization request again
                    if proxies:
                        response = s.post(url,headers=headers,json=postData,verify=False,proxies=proxies)
                    else:
                        response = s.post(url,headers=headers,json=postData,verify=False)

                    responseJSON = json.loads(response.text)

                    if 'errorType' in responseJSON:
                        a = responseJSON['errorType']
                    else:
                        a = responseJSON['categorization'][0]['name']
                else:
                    print('[-] Error: Failed to solve BlueCoat CAPTCHA with OCR! Manually solve at "https://sitereview.bluecoat.com/sitereview.jsp"')
            else:
                print('[-] Error: BlueCoat CAPTCHA received. Try --ocr flag or manually solve a CAPTCHA at "https://sitereview.bluecoat.com/sitereview.jsp"')

        return a

    except Exception as e:
        print('[-] Error retrieving Bluecoat reputation! {0}'.format(e))
        return "error"


def checkIBMXForce(domain, proxies):
    try: 
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
        headers = {'User-Agent':useragent,
                    'Accept':'application/json, text/plain, */*',
                    'x-ui':'XFE',
                    'Origin':url,
                    'Referer':url}

        print('[*] IBM xForce: {}'.format(domain))

        url = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)

        if proxies:
            response = s.get(url,headers=headers,verify=False,proxies=proxies)
        else:
            response = s.get(url,headers=headers,verify=False)

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = responseJSON['error']

        elif not responseJSON['result']['cats']:
            a = 'Uncategorized'
	
	## TO-DO - Add noticed when "intrusion" category is returned. This is indication of rate limit / brute-force protection hit on the endpoint        

        else:
            categories = ''
            # Parse all dictionary keys and append to single string to get Category names
            for key in responseJSON["result"]['cats']:
                categories += '{0}, '.format(str(key))

            a = '{0}(Score: {1})'.format(categories,str(responseJSON['result']['score']))

        return a

    except Exception as e:
        print('[-] Error retrieving IBM-Xforce reputation! {0}'.format(e))
        return "error"


def checkTalos(domain, proxies):
    url = 'https://www.talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry={0}&offset=0&order=ip+asc'.format(domain)
    headers = {'User-Agent':useragent,
               'Referer':url}

    print('[*] Cisco Talos: {}'.format(domain))
    try:
        if proxies:
            response = s.get(url,headers=headers,verify=False,proxies=proxies)
        else:
            response = s.get(url,headers=headers,verify=False)

        responseJSON = json.loads(response.text)

        if 'error' in responseJSON:
            a = str(responseJSON['error'])
            if a == "Unfortunately, we can't find any results for your search.":
                a = 'Uncategorized'
        
        elif responseJSON['category'] is None:
            a = 'Uncategorized'

        else:
            a = '{0} (Score: {1})'.format(str(responseJSON['category']['description']), str(responseJSON['web_score_name']))
       
        return a

    except Exception as e:
        print('[-] Error retrieving Talos reputation! {0}'.format(e))
        return "error"


def checkMXToolbox(domain, proxies):
    url = 'https://mxtoolbox.com/Public/Tools/BrandReputation.aspx'
    headers = {'User-Agent':useragent,
            'Origin':url,
            'Referer':url}  

    print('[*] Google SafeBrowsing and PhishTank: {}'.format(domain))
    
    try:
        if proxies:
            response = s.get(url=url,headers=headers,proxies=proxies)
        else:
            response = s.get(url=url,headers=headers)
        
        soup = BeautifulSoup(response.content,'lxml')

        viewstate = soup.select('input[name=__VIEWSTATE]')[0]['value']
        viewstategenerator = soup.select('input[name=__VIEWSTATEGENERATOR]')[0]['value']
        eventvalidation = soup.select('input[name=__EVENTVALIDATION]')[0]['value']

        data = {
        "__EVENTTARGET": "",
        "__EVENTARGUMENT": "",
        "__VIEWSTATE": viewstate,
        "__VIEWSTATEGENERATOR": viewstategenerator,
        "__EVENTVALIDATION": eventvalidation,
        "ctl00$ContentPlaceHolder1$brandReputationUrl": domain,
        "ctl00$ContentPlaceHolder1$brandReputationDoLookup": "Brand Reputation Lookup",
        "ctl00$ucSignIn$hfRegCode": 'missing',
        "ctl00$ucSignIn$hfRedirectSignUp": '/Public/Tools/BrandReputation.aspx',
        "ctl00$ucSignIn$hfRedirectLogin": '',
        "ctl00$ucSignIn$txtEmailAddress": '',
        "ctl00$ucSignIn$cbNewAccount": 'cbNewAccount',
        "ctl00$ucSignIn$txtFullName": '',
        "ctl00$ucSignIn$txtModalNewPassword": '',
        "ctl00$ucSignIn$txtPhone": '',
        "ctl00$ucSignIn$txtCompanyName": '',
        "ctl00$ucSignIn$drpTitle": '',
        "ctl00$ucSignIn$txtTitleName": '',
        "ctl00$ucSignIn$txtModalPassword": ''
        }
          
        if proxies:
            response = s.post(url=url,headers=headers,data=data,proxies=proxies)
        else:
            response = s.post(url=url,headers=headers,data=data)

        soup = BeautifulSoup(response.content,'lxml')

        a = ''
        if soup.select('div[id=ctl00_ContentPlaceHolder1_noIssuesFound]'):
            a = 'No issues found'
            return a
        else:
            if soup.select('div[id=ctl00_ContentPlaceHolder1_googleSafeBrowsingIssuesFound]'):
                a = 'Google SafeBrowsing Issues Found. '
        
            if soup.select('div[id=ctl00_ContentPlaceHolder1_phishTankIssuesFound]'):
                a += 'PhishTank Issues Found'
            return a

    except Exception as e:
        print('[-] Error retrieving Google SafeBrowsing and PhishTank reputation!')
        return "error"


def downloadMalwareDomains(malwaredomainsURL, proxies):
    url = malwaredomainsURL
    
    if proxies:
        response = s.get(url=url,headers=headers,verify=False,proxies=proxies)
    else:
        response = s.get(url=url,headers=headers,verify=False)

    responseText = response.text
    if response.status_code == 200:
        return responseText
    else:
        print("[-] Error reaching:{}  Status: {}").format(url, response.status_code)


def checkDomain(domain, proxies):
    print('[*] Fetching domain reputation for: {}'.format(domain))

    if domain in maldomainsList:
        malwaredomain = True
        print("[!] {}: Identified as known malware domain (malwaredomains.com)".format(domain))
    else:
        malwaredomain = False
      
    bluecoat = checkBluecoat(domain, proxies)
    print("[+] {}: {}".format(domain, bluecoat))
    
    ibmxforce = checkIBMXForce(domain, proxies)
    print("[+] {}: {}".format(domain, ibmxforce))

    ciscotalos = checkTalos(domain, proxies)
    print("[+] {}: {}".format(domain, ciscotalos))

    mxtoolbox = checkMXToolbox(domain, proxies)
    print("[+] {}: {}".format(domain, mxtoolbox))

    print("")
    
    results = [domain,bluecoat,ibmxforce,ciscotalos,mxtoolbox,malwaredomain]
    return results


def solveCaptcha(url, session, proxies):  
    # Downloads CAPTCHA image and saves to current directory for OCR with tesseract
    # Returns CAPTCHA string or False if error occured
    
    jpeg = 'captcha.jpg'
    
    try:
        if proxies:
            response = session.get(url=url,headers=headers,verify=False,proxies=proxies,stream=True)
        else:
            response = session.get(url=url,headers=headers,verify=False,stream=True)

        if response.status_code == 200:
            with open(jpeg, 'wb') as f:
                response.raw.decode_content = True
                shutil.copyfileobj(response.raw, f)
        else:
            print('[-] Error downloading CAPTCHA file!')
            return False

        # Perform basic OCR without additional image enhancement
        text = pytesseract.image_to_string(Image.open(jpeg))
        text = text.replace(" ", "")
        
        # Remove CAPTCHA file
        try:
            os.remove(jpeg)
        except OSError:
            pass

        return text

    except Exception as e:
        print("[-] Error solving CAPTCHA - {0}".format(e))
        
        return False


def drawTable(header,data):
    
    data.insert(0,header)
    t = Texttable(max_width=maxwidth)
    t.add_rows(data)
    t.header(header)
    
    return(t.draw())



## MAIN
if __name__ == "__main__":


    parser = argparse.ArgumentParser(
        description='Finds expired domains, domain categorization, and Archive.org history to determine good candidates for C2 and phishing domains',
        epilog = '''
Examples:
./domainhunter.py -k apples -c --ocr -t5
./domainhunter.py --check --ocr -t3
./domainhunter.py --single mydomain.com
./domainhunter.py --keyword tech --check --ocr --timing 5 --alexa
./domaihunter.py --filename inputlist.txt --ocr --timing 5''',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-a','--alexa', help='Filter results to Alexa listings', required=False, default=0, action='store_const', const=1)
    parser.add_argument('-k','--keyword', help='Keyword used to refine search results', required=False, default=False, type=str, dest='keyword')
    parser.add_argument('-c','--check', help='Perform domain reputation checks', required=False, default=False, action='store_true', dest='check')
    parser.add_argument('-f','--filename', help='Specify input file of line delimited domain names to check', required=False, default=False, type=str, dest='filename')
    parser.add_argument('--ocr', help='Perform OCR on CAPTCHAs when challenged', required=False, default=False, action='store_true')
    parser.add_argument('-o','--output', help='Output findings to CSV file, used with -f, writes', required=False, default=False, dest='outfile')
    parser.add_argument('-p','--proxy', help='Specify a HTTP/HTTPS proxy server to send requests through. Format: "http(s)://proxyhost:port"', required=False, default=False, dest='proxy')
    parser.add_argument('-r','--maxresults', help='Number of results to return when querying latest expired/deleted domains', required=False, default=100, type=int, dest='maxresults')
    parser.add_argument('-s','--single', help='Performs detailed reputation checks against a single domain name/IP.', required=False, default=False, dest='single')
    parser.add_argument('-t','--timing', help='Modifies request timing to avoid CAPTCHAs. Slowest(0) = 90-120 seconds, Default(3) = 10-20 seconds, Fastest(5) = no delay', required=False, default=3, type=int, choices=range(0,6), dest='timing')
    parser.add_argument('-w','--maxwidth', help='Width of text table', required=False, default=400, type=int, dest='maxwidth')
    parser.add_argument('-V','--version', action='version',version='%(prog)s {version}'.format(version=__version__))
    args = parser.parse_args()

    # Load dependent modules
    try:
        import requests
        from bs4 import BeautifulSoup
        from texttable import Texttable
        
    except Exception as e:
        print("Expired Domains Reputation Check")
        print("[-] Missing basic dependencies: {}".format(str(e)))
        print("[*] Install required dependencies by running `pip3 install -r requirements.txt`")
        quit(0)

    # Load OCR related modules if --ocr flag is set since these can be difficult to get working
    if args.ocr:
        try:
            import pytesseract
            from PIL import Image
            import shutil
        except Exception as e:
            print("Expired Domains Reputation Check")
            print("[-] Missing OCR dependencies: {}".format(str(e)))
            print("[*] Install required Python dependencies by running: pip3 install -r requirements.txt")
            print("[*] Ubuntu\Debian - Install tesseract by running: apt-get install tesseract-ocr python3-imaging")
            print("[*] macOS - Install tesseract with homebrew by running: brew install tesseract")
            quit(0)

## Variables

    alexa = args.alexa

    keyword = args.keyword

    check = args.check

    filename = args.filename
    
    maxresults = args.maxresults

    proxy = args.proxy
    
    single = args.single

    timing = args.timing

    maxwidth = args.maxwidth
    
    ocr = args.ocr

    outfile = args.outfile
    
    malwaredomainsURL = 'http://mirror1.malwaredomains.com/files/justdomains'

    expireddomainsqueryURL = 'https://www.expireddomains.net/domain-name-search'  

    timestamp = time.strftime("%Y%m%d_%H%M%S")
            
    useragent = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'
   
    headers = {'User-Agent':useragent}

    requests.packages.urllib3.disable_warnings()
 
    # HTTP Session container, used to manage cookies, session tokens and other session information
    s = requests.Session()

         
    # Generic Proxy support 
    if proxy:
        proxies = {
            'http': proxy,
            'https': proxy,
        }
    else:
        proxies = False

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

    # Download known malware domains
    print('[*] Downloading malware domain list from {}\n'.format(malwaredomainsURL))
    maldomains = downloadMalwareDomains(malwaredomainsURL, proxies)
    maldomainsList = maldomains.split("\n")

    # Retrieve reputation for a single choosen domain (Quick Mode)
    if single:
        checkDomain(single, proxies)
        exit(0)

    # Perform detailed domain reputation checks against input file, print table, and quit. This does not generate an HTML report
    if filename:
        # Initialize our list with an empty row for the header
        data = []
        try:
            with open(filename, 'r') as domainsList:
                header = ['Domain', 'BlueCoat', 'IBM X-Force', 'Cisco Talos', 'MXToolbox', 'IsMalwareDomain']
                count = 0

                for line in domainsList.read().splitlines():
                    data.append(checkDomain(line, proxies))
                    if outfile: 
                        csvfile = open(outfile, 'a')
                        csvwriter = csv.writer(csvfile)
                        if count == 0:
                             csvwriter.writerow(header)
                        csvwriter.writerow(data[-1])
                        print("[+] Appending CSV data to {}\n".format(outfile))
                        csvfile.close
                        count = count + 1
                    doSleep(timing)

                # Print results table

                print(drawTable(header,data))

                    
                # if outfile:
                #     with open(outfile, 'w') as csvfile:
                #         print("\nWriting CSV data to {}\n".format(outfile))
                #         csvwriter = csv.writer(csvfile)
                #         csvwriter.writerows(data)                     

        except KeyboardInterrupt:
            print('Caught keyboard interrupt. Exiting!')
            exit(0)
        except Exception as e:
            print('[-] Error: {}'.format(e))
            exit(1)
        exit(0)

    # Create an initial session
    if proxy:
        domainrequest = s.get("https://www.expireddomains.net",headers=headers,verify=False,proxies=proxies)
    else:
        domainrequest = s.get("https://www.expireddomains.net",headers=headers,verify=False)

    # Lists for our ExpiredDomains results
    domain_list = []
    data = []

    # Generate list of URLs to query for expired/deleted domains
    urls = []
    
    # Use the keyword string to narrow domain search if provided. This generates a list of URLs to query

    if keyword:
        print('[*] Fetching expired or deleted domains containing "{}"'.format(keyword))
        for i in range (0,maxresults,25):
            if i == 0:
                urls.append("{}/?q={}&fwhois=22&ftlds[]=2&ftlds[]=3&ftlds[]=4&falexa={}".format(expireddomainsqueryURL,keyword,alexa))
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?q={}&start=1'.format(keyword)
            else:
                urls.append("{}/?start={}&q={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&fwhois=22&falexa={}".format(expireddomainsqueryURL,i,keyword,alexa))
                headers['Referer'] ='https://www.expireddomains.net/domain-name-search/?start={}&q={}'.format((i-25),keyword)
    
    # If no keyword provided, generate list of recently expired domains URLS (batches of 25 results).
    else:
        print('[*] Fetching expired or deleted domains...')
        # Caculate number of URLs to request since we're performing a request for two different resources instead of one
        numresults = int(maxresults / 2)
        for i in range (0,(numresults),25):
            urls.append('https://www.expireddomains.net/backorder-expired-domains?start={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&falexa={}'.format(i,alexa))
            urls.append('https://www.expireddomains.net/deleted-com-domains/?start={}&ftlds[]=2&ftlds[]=3&ftlds[]=4&falexa={}'.format(i,alexa))
 
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
        
        if proxy: 
            domainrequest = s.get(url,headers=headers,verify=False,cookies=jar,proxies=proxies)
        else:
            domainrequest = s.get(url,headers=headers,verify=False,cookies=jar)

        domains = domainrequest.text
   
        # Turn the HTML into a Beautiful Soup object
        soup = BeautifulSoup(domains, 'lxml')    
        #print(soup)
        try:
            table = soup.find("table")

            rows = table.findAll('tr')[1:]
            for row in table.findAll('tr')[1:]:

                # Alternative way to extract domain name
                # domain = row.find('td').find('a').text

                cells = row.findAll("td")

                if len(cells) >= 1:
                    if keyword:

                        c0 = row.find('td').find('a').text   # domain
                        c1 = cells[1].find(text=True)   # bl
                        c2 = cells[2].find(text=True)   # domainpop
                        c3 = cells[3].find(text=True)   # birth
                        c4 = cells[4].find(text=True)   # Archive.org entries
                        c5 = cells[5].find(text=True)   # Alexa
                        c6 = cells[6].find(text=True)   # Dmoz.org
                        c7 = cells[7].find(text=True)   # status com
                        c8 = cells[8].find(text=True)   # status net
                        c9 = cells[9].find(text=True)   # status org
                        c10 = cells[10].find(text=True) # status de
                        c11 = cells[11].find(text=True) # TLDs
                        c12 = cells[12].find(text=True) # RDT
                        c13 = cells[13].find(text=True) # List
                        c14 = cells[14].find(text=True) # Status
                        c15 = ""                        # Links 

                        # create available TLD list
                        available = ''
                        if c7 == "available":
                            available += ".com "

                        if c8 == "available":
                            available += ".net "

                        if c9 == "available":
                            available += ".org "

                        if c10 == "available":
                            available += ".de "
                        
                        # Only grab status for keyword searches since it doesn't exist otherwise
                        status = ""
                        if keyword:
                            status = c14
                        
                        # Only add Expired, not Pending, Backorder, etc
                        if c13 == "Expired":
                            # Append parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                            if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                                domain_list.append([c0,c3,c4,available,status]) 

                    # Non-keyword search table format is slightly different
                    else:
                    
                        c0 = cells[0].find(text=True)   # domain
                        c1 = cells[1].find(text=True)   # bl
                        c2 = cells[2].find(text=True)   # domainpop
                        c3 = cells[3].find(text=True)   # birth
                        c4 = cells[4].find(text=True)   # Archive.org entries
                        c5 = cells[5].find(text=True)   # Alexa
                        c6 = cells[6].find(text=True)   # Dmoz.org
                        c7 = cells[7].find(text=True)   # status com
                        c8 = cells[8].find(text=True)   # status net
                        c9 = cells[9].find(text=True)   # status org
                        c10 = cells[10].find(text=True) # status de
                        c11 = cells[11].find(text=True) # TLDs
                        c12 = cells[12].find(text=True) # RDT
                        c13 = cells[13].find(text=True) # End Date
                        c14 = cells[14].find(text=True) # Links
                        
                        # create available TLD list
                        available = ''
                        if c7 == "available":
                            available += ".com "

                        if c8 == "available":
                            available += ".net "

                        if c9 == "available":
                            available += ".org "

                        if c10 == "available":
                            available += ".de "

                        status = ""

                        # Append original parsed domain data to list if it matches our criteria (.com|.net|.org and not a known malware domain)
                        if (c0.lower().endswith(".com") or c0.lower().endswith(".net") or c0.lower().endswith(".org")) and (c0 not in maldomainsList):
                            domain_list.append([c0,c3,c4,available,status]) 
                        
        except Exception as e: 
            print("[!] Error: ", e)
            pass

        # Add additional sleep on requests to ExpiredDomains.net to avoid errors
        time.sleep(5)

    # Check for valid list results before continuing
    if len(domain_list) == 0:
        print("[-] No domain results found or none are currently available for purchase!")
        exit(0)
    else:
        domain_list_unique = []
        [domain_list_unique.append(item) for item in domain_list if item not in domain_list_unique]

        # Print number of domains to perform reputation checks against
        if check:
            print("\n[*] Performing reputation checks for {} domains".format(len(domain_list_unique)))

        for domain_entry in domain_list_unique:
            domain = domain_entry[0]
            birthdate = domain_entry[1]
            archiveentries = domain_entry[2]
            availabletlds = domain_entry[3]
            status = domain_entry[4]
            bluecoat = '-'
            ibmxforce = '-'
            ciscotalos = '-'

            # Perform domain reputation checks
            if check:
                
                bluecoat = checkBluecoat(domain, proxies)
                print("[+] {}: {}".format(domain, bluecoat))
                ibmxforce = checkIBMXForce(domain, proxies)
                print("[+] {}: {}".format(domain, ibmxforce))
                ciscotalos = checkTalos(domain, proxies)
                print("[+] {}: {}".format(domain, ciscotalos))
                print("")
                # Sleep to avoid captchas
                doSleep(timing)

            # Append entry to new list with reputation if at least one service reports reputation
            if not ((bluecoat in ('Uncategorized','badurl','Suspicious','Malicious Sources/Malnets','captcha','Phishing','Placeholders','Spam','error')) \
                and (ibmxforce in ('Not found.','error')) and (ciscotalos in ('Uncategorized','error'))):
                
                data.append([domain,birthdate,archiveentries,availabletlds,status,bluecoat,ibmxforce,ciscotalos])

    # Sort domain list by column 2 (Birth Year)
    sortedDomains = sorted(data, key=lambda x: x[1], reverse=True) 

    if check:
        if len(sortedDomains) == 0:
            print("[-] No domains discovered with a desireable categorization!")
            exit(0)
        else:
            print("[*] {} of {} domains discovered with a potentially desireable categorization!".format(len(sortedDomains),len(domain_list)))

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
                    <th>BlueCoat</th>
                    <th>IBM X-Force</th>
                    <th>Cisco Talos</th>
                    <th>WatchGuard</th>
                    <th>Namecheap</th>
                    <th>Archive.org</th>
                 '''

    htmlTableBody = ''
    htmlTableFooter = '</table>'
    htmlFooter = '</body></html>'

    # Build HTML table contents
    for i in sortedDomains:
        htmlTableBody += '<tr>'
        htmlTableBody += '<td>{}</td>'.format(i[0]) # Domain
        htmlTableBody += '<td>{}</td>'.format(i[1]) # Birth
        htmlTableBody += '<td>{}</td>'.format(i[2]) # Entries
        htmlTableBody += '<td>{}</td>'.format(i[3]) # TLDs
        htmlTableBody += '<td>{}</td>'.format(i[4]) # Status

        htmlTableBody += '<td><a href="https://sitereview.bluecoat.com/" target="_blank">{}</a></td>'.format(i[5]) # Bluecoat
        htmlTableBody += '<td><a href="https://exchange.xforce.ibmcloud.com/url/{}" target="_blank">{}</a></td>'.format(i[0],i[6]) # IBM x-Force Categorization
        htmlTableBody += '<td><a href="https://www.talosintelligence.com/reputation_center/lookup?search={}" target="_blank">{}</a></td>'.format(i[0],i[7]) # Cisco Talos
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
    header = ['Domain', 'Birth', '#', 'TLDs', 'Status', 'BlueCoat', 'IBM', 'Cisco Talos']
    print(drawTable(header,sortedDomains))
