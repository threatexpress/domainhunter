# Domain Hunter

Authors Joe Vest (@joevest) & Andrew Chiles (@andrewchiles)

Domain name selection is an important aspect of preparation for penetration tests and especially Red Team engagements. Commonly, domains that were used previously for benign purposes and were properly categorized can be purchased for only a few dollars. Such domains can allow a team to bypass reputation based web filters and network egress restrictions for phishing and C2 related tasks. 

This Python based tool was written to quickly query the Expireddomains.net search engine for expired/available domains with a previous history of use. It then optionally queries for domain reputation against services like BlueCoat and IBM X-Force. The primary tool output is a timestamped HTML table style report.

## Changes

    - June 6 2017
        + Added python 3 support
        + Code cleanup and bug fixes
        + Added Status column (Available, Make Offer, Price,Backorder,etc)

## Features

- Retrieves specified number of recently expired and deleted domains (.com, .net, .org primarily)
- Retrieves available domains based on keyword search
- Reads line delimited input file of potential domains names to check against reputation services
- Performs reputation checks against the Blue Coat Site Review and IBM x-Force services
- Sorts results by domain age (if known)
- Text-based table and HTML report output with links to reputation sources and Archive.org entry

## Usage

Install Requirements

    pip install -r requirements.txt
    or
    pip install requests texttable beautifulsoup4 lxml

List DomainHunter options
    
    python ./domainhunter.py
    usage: domainhunter.py [-h] [-q QUERY] [-c] [-r MAXRESULTS] [-w MAXWIDTH]

    Checks expired domains, bluecoat categorization, and Archive.org history to
    determine good candidates for C2 and phishing domains

    optional arguments:
      -h, --help            show this help message and exit
      -q QUERY, --query QUERY
                            Optional keyword used to refine search results
      -c, --check         Perform slow reputation checks
      -r MAXRESULTS, --maxresults MAXRESULTS
                            Number of results to return when querying latest
                            expired/deleted domains (min. 100)

Use defaults to check for most recent 100 domains and check reputation
    
    python ./domainhunter.py

Search for 1000 most recently expired/deleted domains, but don't check reputation against Bluecoat or IBM xForce

    python ./domainhunter.py -r 1000 -n

Retreive reputation information from domains in an input file

    python ./domainhunter.py -f <filename>

Search for available domains with search term of "dog" and max results of 100
    
    ./domainhunter.py -q dog -r 100 -c
     ____   ___  __  __    _    ___ _   _   _   _ _   _ _   _ _____ _____ ____
    |  _ \ / _ \|  \/  |  / \  |_ _| \ | | | | | | | | | \ | |_   _| ____|  _ \
    | | | | | | | |\/| | / _ \  | ||  \| | | |_| | | | |  \| | | | |  _| | |_) |
    | |_| | |_| | |  | |/ ___ \ | || |\  | |  _  | |_| | |\  | | | | |___|  _ <
    |____/ \___/|_|  |_/_/   \_\___|_| \_| |_| |_|\___/|_| \_| |_| |_____|_| \_\

    Expired Domains Reputation Checker

    DISCLAIMER:
    This is for educational purposes only!
    It is designed to promote education and the improvement of computer/cyber security.
    The authors or employers are not liable for any illegal act or misuse performed by any user of this tool.
    If you plan to use this content for illegal purpose, don't.  Have a nice day :)

    ********************************************
    Start Time:             20170301_113226
    TextTable Column Width: 400
    Checking Reputation:    True
    Number Domains Checked: 100
    ********************************************
    Estimated Max Run Time: 33 minutes

    [*] Downloading malware domain list from http://mirror1.malwaredomains.com/files/justdomains
    [*] Fetching expired or deleted domains containing "dog"...
    [*]  https://www.expireddomains.net/domain-name-search/?q=dog
    [*] BlueCoat Check: Dog.org.au
    [+] Dog.org.au is categorized as: Uncategorized
    [*] IBM xForce Check: Dog.org.au
    [+] Dog.org.au is categorized as: Not found.
    [*] BlueCoat Check: Dog.asia
    [+] Dog.asia is categorized as: Uncategorized
    [*] IBM xForce Check: Dog.asia
    [+] Dog.asia is categorized as: Not found.
    [*] BlueCoat Check: HomeDog.net
    [+] HomeDog.net is categorized as: Uncategorized
    [*] IBM xForce Check: HomeDog.net
    [+] HomeDog.net is categorized as: Not found.
    [*] BlueCoat Check: PolyDogs.com
    [+] PolyDogs.com is categorized as: Uncategorized
    [*] IBM xForce Check: PolyDogs.com
    [+] PolyDogs.com is categorized as: Not found.
    [*] BlueCoat Check: SaltyDog.it
    [+] SaltyDog.it is categorized as: Uncategorized
    [*] IBM xForce Check: SaltyDog.it
    [+] SaltyDog.it is categorized as: Not found.
    [*]  https://www.expireddomains.net/domain-name-search/?start=25&q=dog
    [*] BlueCoat Check: FetchDoggieStore.com
    [+] FetchDoggieStore.com is categorized as: Society/Daily Living
    [*] IBM xForce Check: FetchDoggieStore.com
    [+] FetchDoggieStore.com is categorized as: {u'General Business': True}

## Report Header Reference

 - Domain: Target Domain
 - Birth: First seen on Archive.org
 - Entries: Number of entries in Archive.org
 - TLDs Available: Top level top available
 - Bluecoat Categorization: Bluecoat category
 - IBM-xForce Categorization: IBM-xForce category
 - WatchGuard: Watchguard reputation
 - Namecheap: Link to namecheap.com
 - Archive.org: Link to archive.org