#!/usr/bin/env python


#############################################################
#
# Usage: ./pysoftnews [Options]
#
#############################################################

import sys
import datetime
from optparse import OptionParser
import xml.etree.cElementTree as ET
import re
import requests
from bs4 import BeautifulSoup
import bleach


# Add more URLs!

user_agent = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0' }


apache_url = 'http://httpd.apache.org'
php_url = 'http://php.net'
joomla_url = 'https://www.joomla.org/announcements/release-news'
nginx_url = 'http://nginx.org/'
openssl_url = 'https://www.openssl.org/news/newslog.html'
tomcat_url = 'http://tomcat.apache.org/'
lighthttp_url = 'http://www.lighttpd.net/download/'
wordpress_url = "https://wordpress.org/news/"
drupal_url = 'https://www.drupal.org/news/'
proftpd_url = 'http://www.proftpd.org/'
moodle_url = 'https://moodle.org/news/'
django_url = 'https://www.djangoproject.com/weblog/'
phpmyadmin_url = 'http://www.phpmyadmin.net/home_page/news.php'
primefaces_url = 'http://blog.primefaces.org/'
postgresql_url = 'http://www.postgresql.org/about/newsarchive/'
mysql_url = 'http://www.mysql.com/news-and-events/'
mariadb_url = 'https://mariadb.org/'
mongodb_url = 'https://www.mongodb.com/press'
elasticsearch_url = 'https://www.elastic.co/blog'
openssh_url = 'http://www.openssh.com/security.html'
mediawiki_url = 'https://www.mediawiki.org/wiki/News'
openvas_url = 'http://www.openvas.org/news.html'
zaproxy_url = 'https://www.owasp.org/index.php/Projects/OWASP_Zed_Attack_Proxy_Project/Pages/News'
rubyonrails_url = 'http://weblog.rubyonrails.org/'
arachni_url = 'http://www.arachni-scanner.com/blog/'
nessus_url = 'http://www.tenable.com/media/press-releases'
F5_url = 'https://support.f5.com/kb/en-us.html'

# Security Advisories
vmware_url_security = 'https://www.vmware.com/security/advisories'
drupal_url_security = 'https://www.drupal.org/security'
squid_url_security = 'http://www.squid-cache.org/Advisories/'
joomla_url_security = 'http://developer.joomla.org/security-centre.html'
cisco_url_security = 'http://tools.cisco.com/security/center/publicationListing.x'
ossec_url_security = 'http://www.ossec.net/?page_id=134'
owncloud_url_security = 'https://owncloud.org/wp-content/themes/owncloudorgnew/advisories/advisories.rss'

# Literals
news = "news"


# Format of the data array ("string with the software name", var (with url), "type")
# Where type is news, security, ...

# Add more!!

data = [("Apache", apache_url, "news"),
    ("PHP", php_url, "news"),
    ("Nginx", nginx_url, "news"),
    ("OpenSSL", openssl_url, "news"),
    ("Tomcat", tomcat_url, "news"),
    ("Wordpress", wordpress_url, "news"),
    ("Drupal", drupal_url, "news"),
    ("Django", django_url, "news"),
    ("PHPMyAdmin", phpmyadmin_url, "news"),
    ("PrimeFaces", primefaces_url, "news"),
    ("ProFTPD", proftpd_url, "news"),
    ("Moodle", moodle_url, "news"),
    ("MySQL", mysql_url, "news"),
    ("MariaDB", mariadb_url, "news"),
    ("OpenSSH", openssh_url, "news"),
    ("MediaWiki", mediawiki_url, "news"),
    ("Zaproxy", zaproxy_url, "news"),
    ("OpenVAS", openvas_url, "news"),
    ("Ruby on rails", rubyonrails_url, "news"),
    ("MongoDB", mongodb_url, "news"),
    ("Postgresql", postgresql_url, "news"),
    ("Joomla", joomla_url, "news"),
    ("VMWare", vmware_url_security, "security"),
    ("Drupal", drupal_url_security, "security"),
    ("Squid", squid_url_security, "security"),
    ("Arachni", arachni_url, "news"),
    ("Joomla", joomla_url_security, "security"),
    ("Cisco", cisco_url_security, "security"),
    ("OSSEC", ossec_url_security, "security"),
    ("Nessus", nessus_url, "news"),
    ("F5", F5_url, "news"),
    ("Owncloud", owncloud_url_security, "security")]


data_output = []

#FORMAT
XML = "xml"

class Software:
    def __init__(self, name, url, type_news, mode):
        self.name = name
        self.news = ""
        self.url = url
        self.date = ""
        self.type = type_news
        self.mode = mode

    def getName(self):
        ''' Return the sanitized name'''
        return bleach.clean(self.name)

    def getNews(self):
        ''' Return the sanitized news'''
        return bleach.clean(self.news)

    def getURL(self):
        ''' Return the URL'''
        return bleach.clean(self.url)

    def getDate(self):
        ''' Return the date'''
        return bleach.clean(self.date)

    def getType(self):
        ''' Return the news type'''
        return self.type

    def getData(self):
        try:
            requests.packages.urllib3.disable_warnings()
            r = requests.get(self.url, verify=False, headers=user_agent)
            soup = BeautifulSoup(r.text, "html5lib")

            if (self.name == 'Apache'):
                self.date = datetime.datetime.strptime(soup.find_all('div')[2].find_all('h1')[1].span.text, "%Y-%m-%d").strftime("%d-%m-%Y").encode('utf-8')
                self.news = soup.find_all('div')[2].find_all('h1')[1].text.replace(soup.find_all('div')[2].find_all('h1')[1].span.text, "").encode('utf-8')
            elif (self.name == 'Tomcat'):
                self.date = datetime.datetime.strptime(soup.find_all('h3')[1].span.text, "%Y-%m-%d").strftime("%d-%m-%Y")
                self.news = soup.find_all('h3')[1].text.replace(soup.find_all('h3')[1].span.text,"").replace('\n','').encode('utf-8')
            elif (self.name == 'Drupal'):
                self.date = datetime.datetime.strptime(soup.find_all('time')[0].text.split(" at")[0],"%d %B %Y").strftime("%d-%m-%Y")
		if (self.type == 'security'):
			self.news = soup.find_all('div',attrs={'class':'view-content'})[0].find_all('h2')[0].text.encode('utf-8')
		else:
			self.news = soup.find_all('div',attrs={'class':'view-content'})[0].find_all("h2")[0].text.encode("utf-8")
            elif (self.name == 'Nginx'):
                self.date = datetime.datetime.strptime(soup.find_all('td',attrs={'class':'date'})[0].text,"%Y-%m-%d").strftime("%d-%m-%Y")
                self.news = soup.find_all('td')[1].text.replace('\n',' ').encode('utf-8')
            elif (self.name == 'PHP'):
                self.date = datetime.datetime.strptime(soup.find_all('time')[0].text,"%d %b %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('article')[0].find('h2').text.replace('\n','').encode('utf-8')
            elif (self.name == 'Wordpress'):
                self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'meta'})[0].text.split('by')[0].replace('Posted ',''),"%B %d, %Y ").strftime("%d-%m-%Y")
                self.news = soup.find_all('h2',attrs={'class':'fancy'})[0].text.encode('utf-8')
            elif (self.name == 'ProFTPD'):
                self.date = datetime.datetime.strptime(soup.find_all('div',id="content")[0].find_all('i')[0].text,"%d/%b/%Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('div',id="content")[0].find_all('h1')[0].text.encode('utf-8')
            elif (self.name == 'OpenSSL'):
                self.date = datetime.datetime.strptime(soup.find_all('table')[0].find_all('tr')[1].td.text,"%d-%b-%Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('table')[0].find_all('tr')[1].find_all('td')[1].text.strip().encode('utf-8')
            elif (self.name == 'Moodle'):
                self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'author-date'})[0].text,"%A, %d %B %Y, %I:%M %p").strftime("%d-%m-%Y")
                self.news = soup.find_all('div',attrs={'class':'subject'})[0].text.encode('utf-8')
            elif (self.name == 'Django'):
                creatorDate =  soup.find('ul',attrs={'class':'list-news'}).find_all('li')[0].span.text.split('on')
                self.date = datetime.datetime.strptime(creatorDate[len(creatorDate)-1].strip(),"%B %d, %Y").strftime("%d-%m-%Y")
                self.news = (soup.find('ul',attrs={'class':'list-news'}).find_all('li')[0].h2.text).strip().encode('utf-8')
            elif (self.name == 'PHPMyAdmin'):
                self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'hentry'})[0].find('p',attrs={'class':'date'}).text,"%Y-%m-%d").strftime("%d-%m-%Y")
                self.news = soup.find_all('div',attrs={'class':'hentry'})[0].h2.text.strip().encode('utf-8')
            elif (self.name == 'PrimeFaces'):
                self.date = str(datetime.datetime.strptime(soup.find_all('div',attrs={'class':'entry-meta'})[0].a.text,"%B %d, %Y").strftime("%d-%m-%Y"))
                self.news = soup.find_all('h1',attrs={'class':'entry-title'})[0].text.strip().encode('utf-8')
            elif (self.name == 'Postgresql'):
                self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'pgContentWrap'}).find_all('div')[0].text,"Posted on %Y-%m-%d").strftime("%d-%m-%Y")
                self.news =  soup.find('div',attrs={'id':'pgContentWrap'}).find_all('h2')[0].text.strip().encode('utf-8')
            elif (self.name == 'MySQL'):
                self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'page'}).find_all('p')[0].span.text,"%d %B %Y").strftime("%d-%m-%Y")
                self.news = soup.find('div',attrs={'id':'page'}).find_all('h3')[0].text.strip().encode('utf-8')
            elif (self.name == 'MariaDB'):
                self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'recent-posts-4'}).find_all('span')[0].text.strip(),"%Y-%m-%d").strftime("%d-%m-%Y")
                self.news = soup.find('div',attrs={'id':'recent-posts-4'}).find_all('a')[0].text.encode('utf-8').strip()
            elif (self.name == 'MongoDB'):
                self.date = datetime.datetime.strptime(soup.find_all('p',attrs={'class':'font--light-green'})[0].text,"%B %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('p',attrs={'class':'margin--top-none'})[0].text.strip().encode('utf-8')
            elif (self.name == 'elasticsearch'):
                self.date = datetime.datetime.strptime(soup.find('ul',attrs={'class':'blog-details'}).find_all('li')[0].span.text,"%B %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find('ul',attrs={'class':'blog-details'}).find_all('li')[0].a.text.split("-")[0].encode('utf-8')
            elif (self.name == 'OpenSSH'):
                self.date = datetime.datetime.strptime(soup.find_all('li')[0].strong.text,"%B %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('li')[0].br.next_sibling.strip().encode('utf-8')
            elif (self.name == 'MediaWiki'):
                self.date = datetime.datetime.strptime(soup.find_all('dl')[0].text.strip(),"%Y-%m-%d").strftime("%d-%m-%Y")
                self.news = soup.find_all('ul')[1].text.strip().encode('utf-8')
            elif (self.name == 'OpenVAS'):
                aux = soup.find_all('div',attrs={'class':'content'})[0].h3.text.split("-")[0]
                aux_re = re.sub(r"\b([0123]?[0-9])(st|th|nd|rd)\b",r"\1",aux)
                self.date = datetime.datetime.strptime(aux_re,"%B %d, %Y ").strftime("%d-%m-%Y")
                self.news = " ".join(soup.find_all('div',attrs={'class':'content'})[0].h3.text.split("-")[1:]).encode('utf-8')
            elif (self.name == 'Zaproxy'):
                self.date = datetime.datetime.strptime(soup.find_all('li')[0].text.strip().split(" ")[0],"%Y/%m/%d").strftime("%d-%m-%Y")
                self.news = " ".join(soup.find_all('li')[0].text.strip().split(" ")[1:]).encode('utf-8')
            elif (self.name == 'Ruby on rails'):
                self.date = datetime.datetime.strptime(soup.find_all('span',attrs={'class':'published'})[0].get('title'),"%Y-%m-%d %X +0000").strftime("%d-%m-%Y")
                self.news = soup.find_all('h2')[0].text.strip().encode('utf-8')
            elif (self.name == "Joomla"):
                if (self.type == 'security'):
                    self.date = datetime.datetime.strptime(soup.find_all('h2', attrs={'itemprop' :'name'})[0].text.strip().split('-')[0],"[%Y%m%d] ").strftime("%d-%m-%Y")
                    self.news = soup.find_all('h2', attrs={'itemprop' :'name'})[0].text.strip()[soup.find_all('h2', attrs={'itemprop' :'name'})[0].text.strip().index('-')+2:].encode('utf-8')
                else:
                    self.date = datetime.datetime.strptime(soup.find_all('time',attrs={'itemprop':'dateCreated'})[0].get('datetime').split('T')[0],'%Y-%m-%d').strftime("%d-%m-%Y")
                    self.news = soup.find_all('h2',attrs={'itemprop':'name'})[0].a.text.strip().encode('utf-8')
            elif (self.name == "VMWare"):
                self.date = datetime.datetime.strptime(soup.find_all('div', attrs={'class':'news_block'})[0].p.text, "%B %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('div', attrs={'class':'news_block'})[0].find_all('p', attrs={'class':'advisory-listing'})[0].text.strip().encode('utf-8')
            elif (self.name == "Squid"):
                datetuple = " ".join(soup.find_all("dt")[0].text.split(",")[1:]).rsplit(" ",4)[-4:]
                self.date = datetime.datetime.strptime(" ".join(datetuple), "%b %d  %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all("dd")[0].text.strip().encode('utf-8')
            elif (self.name == "Arachni"):
                self.date = datetime.datetime.strptime(soup.find_all('span', attrs={'class':'entry-date'})[0].text, "%B %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('a', attrs={'rel':'bookmark'})[0].text.encode('utf-8')
            elif (self.name == "Cisco"):
                self.date = datetime.datetime.strptime(soup.find_all('tr', attrs={'class': 'apps-table-data'})[0].find_all('td')[3].text.strip().split('\n\t')[0], "%Y %b %d ").strftime("%d-%m-%Y")
                self.news = soup.find_all('tr', attrs={'class': 'apps-table-data'})[0].find_all('td')[0].text.strip().split("\n\t")[0].encode('utf-8')
            elif (self.name == "OSSEC"):
                self.date = datetime.datetime.strptime(soup.find_all('ul', attrs={'class':'ablog-archive'})[0].find_all('li')[0].text.strip(),"%b %d, %Y").strftime("%d-%m-%Y").encode('utf-8')
                self.news = soup.find_all('h2')[0].text.encode('utf-8').strip().encode('utf-8')
            elif (self.name == "Nessus"):
                self.date = datetime.datetime.strptime(soup.find_all('em')[0].text,"%b %d, %Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('h5')[0].text.strip().encode('utf-8')
            elif (self.name == "F5"):
                self.date = datetime.datetime.strptime(soup.find_all('td', attrs={'class': 'date'})[0].text.strip(), "%m/%d/%Y").strftime("%d-%m-%Y")
                self.news = soup.find_all('td', attrs={'class': 'description'})[0].text.strip().encode('utf-8')
            elif (self.name == "Owncloud"):
                self.date = datetime.datetime.strptime(soup.find_all("pubdate")[1].text,"%a, %d %b %Y %H:%M:%S +0100").strftime("%d-%m-%Y")
                self.news = soup.find_all("title")[1].text.text.strip().encode('utf-8')
            else:
                self.date = "01-01-1970"
                self.news = "ERROR"
        except Exception as e:
                if (self.mode is not None):
                    #Debug mode
                    print("[ERR] %s"%str(e))
                self.date = "01-01-1970"
                self.news = "ERROR"


    def __repr__(self):
        return repr((self.name, self.date, self.url, self.news))

    def __str__(self):
        return "[*] Name: %s\n[+] Date: %s\n[+] Last News: %s\n[+] URL: %s" % (self.name,
                    self.date, self.news, self.url)


def opciones():
        parser = OptionParser("usage: %prog [options] \nExample: ./%prog -n drupal,django")
        # TODO: parametros -F --format xml,json,csv,...
        # TODO: Add parameter to filter by a date range
        parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", help="Verbose")
        parser.add_option("-d", "--debug",
                  action="store_true", dest="debug", help="Debug")
        parser.add_option("-A", "--all",
                  action="store_true", dest="all", help="All software")
        parser.add_option("-t", "--type",
                  action="store", type="string", dest="type", help="News type (news, security)")
        parser.add_option("-f", "--format",
                  action="store", type="string", dest="format", help="Output format")
        parser.add_option("-o", "--output",
                  action="store", type="string", dest="output", help="Filename output")
        parser.add_option("-n", "--name",
                  action="store", type="string", dest="name", help="Software name(s)")
        (options, args) = parser.parse_args()
        if (len(sys.argv) == 1):
            parser.print_help()
        elif (options.all):
            if (options.output is not None):
                if (options.format is not None):
                    # Save all soft in output list
                    for i in data:
                        if (options.verbose):
                            print("[/] %s" % i[0])
                        # check news type (news or security)
                        if (options.type == 'security') and (i[2] == "security"):
                            software_aux = Software(i[0], i[1], i[2], options.debug)
                            software_aux.getData()
                            data_output.append(software_aux)
                        elif (options.type == "news") and (i[2] == "news"):
                            software_aux = Software(i[0], i[1], i[2], options.debug)
                            software_aux.getData()
                            data_output.append(software_aux)
                        elif (options.type is None):
                            software_aux = Software(i[0], i[1], i[2], options.debug)
                            software_aux.getData()
                            data_output.append(software_aux)
                    if (options.format == XML):
                        printXML(data_output, options.output)
                    # TODO: Add more formats!
                else:
                    print("[-] Fail: need format output (e.g -f xml)")
            else:
                    printAll(type_news=options.type)
        elif (options.name is not None):
            if (options.output is not None):
                if (options.format is not None):
                    for name in options.name.split(","):
                        addList(name.strip(), options.debug)
                    if (options.format == XML):
                        printXML(data_output, options.output)
                else:
                    print("[-] Fail: need format output (e.g -f xml)")
            else:
                if (len(options.name.split(",")) > 0):
                    for name in options.name.split(","):
                        printNormal(name.strip(), options.type, options.debug)
                else:
                    printNormal(options.name, options.type, options.debug)
        else:
            print("[-] Fail: All or name parameter")


def getURL(name2find, type_news=news):
    try:
        if type_news is None:
            type_news = news
        software = None
        for x in data:
            name = x[0].upper()
            type_n = x[2].upper()
            if (name == name2find.upper()) and (type_news.upper() == type_n.upper()):
                software = x
        return software
    except ValueError:
        return None
    except TypeError:
        return None


def printNormal(name2find, type_news, mode):
    try:
        (name, url, type_news) = getURL(name2find, type_news)
        if url is not None:
            software = Software(name, url, type_news, mode)
            software.getData()
            print(software)
        else:
            print("[-] Name %s Not found." % name2find)
    except TypeError:
        print("[-] Name %s Not found." % name2find)


def addList(name2find, mode):
    '''Add data info to the global list'''
    try:
        (name, url, type_news) = getURL(name2find)
        if url is not None:
            software = Software(name, url, type_news, mode)
            software.getData()
            data_output.append(software)
    except TypeError:
        pass


def printJSON(filename):
    '''TODO'''
    return None


def printAll(type_news, mode):
    '''Print all list'''
    for i in data:
        if (type_news == "security") and (i[2] == "security"):
            software = Software(i[0], i[1], i[2], mode)
            software.getData()
            print(software)
        elif (type_news == "news") and (i[2] == "news"):
            software = Software(i[0], i[1], i[2], mode)
            software.getData()
            print(software)
        elif (type_news is None):
            software = Software(i[0], i[1], i[2], mode)
            software.getData()
            print(software)


def printXML(data_output, filename):
    '''Create a XML file with the output'''
    orderList = sorted(data_output, key=lambda software: datetime.datetime.strptime(software.date,"%d-%m-%Y"), reverse=True)

    # Create XML
    root = ET.Element("news")
    for i in orderList:
        software = ET.SubElement(root, "software")
        ET.SubElement(software, "name").text = i.getName()
        ET.SubElement(software, "lastNews").text = i.getNews()
        ET.SubElement(software, "date").text = i.getDate()
        ET.SubElement(software, "url").text = i.getURL()
        tree = ET.ElementTree(root)
        tree.write(filename)

if __name__ == "__main__":
    opciones()

