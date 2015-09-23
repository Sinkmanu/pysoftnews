#!/usr/bin/env python


#############################################################
#
# Usage: ./pysoftnews [Options]
#
# Last update: 17/09/2015
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
mongodb_url = 'https://www.mongodb.com/news'
elasticsearch_url = 'https://www.elastic.co/blog'
openssh_url = 'http://www.openssh.com/security.html'
mediawiki_url = 'https://www.mediawiki.org/wiki/News'
openvas_url = 'http://www.openvas.org/news.html'
zaproxy_url = 'https://www.owasp.org/index.php/Projects/OWASP_Zed_Attack_Proxy_Project/Pages/News'
rubyonrails_url = 'http://weblog.rubyonrails.org/'


# Add more!!

data = [("Apache", apache_url), ("PHP", php_url), ("Nginx", nginx_url),
    ("OpenSSL", openssl_url), ("Tomcat", tomcat_url), ("Wordpress", wordpress_url),
    ("Drupal", drupal_url), ("Django", django_url), ("PHPMyAdmin", phpmyadmin_url),
    ("PrimeFaces", primefaces_url), ("ProFTPD", proftpd_url), ("Moodle", moodle_url),
    ("MySQL", mysql_url), ("MariaDB", mariadb_url), ("OpenSSH", openssh_url),
    ("MediaWiki", mediawiki_url), ("Zaproxy", zaproxy_url), ("OpenVAS", openvas_url),
    ("Ruby on rails", rubyonrails_url), ("MongoDB", mongodb_url),
    ("Postgresql", postgresql_url), ("Joomla", joomla_url)]


data_output = []

#FORMAT
XML = "xml"

class Software:
    def __init__(self, name, url):
        self.name = name
        self.news = ""
        self.url = url
        self.date = ""

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

    def getData(self):
        try:
            requests.packages.urllib3.disable_warnings()
            r = requests.get(self.url, verify=False, headers = user_agent)
            soup = BeautifulSoup(r.text, "html5lib")
        except requests.InsecureRequestWarning:
            pass

        if (self.name == 'Apache'):
            self.date = datetime.datetime.strptime(soup.find_all('div')[2].find_all('h1')[1].span.text,"%Y-%m-%d").strftime("%d-%m-%Y")
            self.news = soup.find_all('div')[2].find_all('h1')[1].text.replace(soup.find_all('div')[2].find_all('h1')[1].span.text,'')
        elif (self.name == 'Tomcat'):
            self.date = datetime.datetime.strptime(soup.find_all('h3')[1].span.text,"%Y-%m-%d").strftime("%d-%m-%Y")
            self.news = soup.find_all('h3')[1].text.replace(soup.find_all('h3')[1].span.text,"").replace('\n','')
        elif (self.name == 'Drupal'):
            self.date = datetime.datetime.strptime(soup.find_all('time')[0].text.split(" at")[0],"%B %d, %Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('div',attrs={'class':'content'})[2].a.text
        elif (self.name == 'Nginx'):
            self.date = datetime.datetime.strptime(soup.find_all('td',attrs={'class':'date'})[0].text,"%Y-%m-%d").strftime("%d-%m-%Y")
            self.news = soup.find_all('td')[1].text.replace('\n',' ')
        elif (self.name == 'PHP'):
            self.date = datetime.datetime.strptime(soup.find_all('time')[0].text,"%d %b %Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('article')[0].find('h2').text.replace('\n','')
        elif (self.name == 'Wordpress'):
            self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'meta'})[0].text.split('by')[0].replace('Posted ',''),"%B %d, %Y ").strftime("%d-%m-%Y")
            self.news = soup.find_all('h2',attrs={'class':'fancy'})[0].text
        elif (self.name == 'ProFTPD'):
            self.date = datetime.datetime.strptime(soup.find_all('div',id="content")[0].find_all('i')[0].text,"%d/%B/%Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('div',id="content")[0].find_all('h1')[0].text
        elif (self.name == 'OpenSSL'):
            self.date = datetime.datetime.strptime(soup.find_all('table')[0].find_all('tr')[1].td.text,"%d-%b-%Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('table')[0].find_all('tr')[1].find_all('td')[1].text.strip()
        elif (self.name == 'Moodle'):
            self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'author-date'})[0].text,"%A, %d %B %Y, %I:%M %p").strftime("%d-%m-%Y")
            self.news = soup.find_all('div',attrs={'class':'subject'})[0].text
        elif (self.name == 'Django'):
            self.date = datetime.datetime.strptime(soup.find('ul',attrs={'class':'list-news'}).find_all('li')[0].span.text.split('on')[1].strip(),"%B %d, %Y").strftime("%d-%m-%Y")
            self.news = (soup.find('ul',attrs={'class':'list-news'}).find_all('li')[0].h2.text).strip()
        elif (self.name == 'PHPMyAdmin'):
            self.date = datetime.datetime.strptime(soup.find_all('div',attrs={'class':'hentry'})[0].find('p',attrs={'class':'date'}).text,"%Y-%m-%d").strftime("%d-%m-%Y")
            self.news = soup.find_all('div',attrs={'class':'hentry'})[0].h2.text.strip()
        elif (self.name == 'PrimeFaces'):
            self.date = str(datetime.datetime.strptime(soup.find_all('span',attrs={'class':'entry-date'})[0].text,"%B %d, %Y").strftime("%d-%m-%Y"))
            self.news = soup.find_all('h2',attrs={'class':'entry-title'})[0].text.strip()
        elif (self.name == 'Postgresql'):
	    date_month =  soup.find('div',attrs={'id':'pgContentWrap'}).find_all('div')[0].text.split(" ")[2]
	    if (date_month == 'Sept.'):
            	self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'pgContentWrap'}).find_all('div')[0].text.split(".")[1]," %d, %Y").replace(month = 9).strftime("%d-%m-%Y")
	    else:
 		self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'pgContentWrap'}).find_all('div')[0].text,"Posted on %b. %d, %Y").strftime("%d-%m-%Y")
            self.news =  soup.find('div',attrs={'id':'pgContentWrap'}).find_all('h2')[0].text.strip()
        elif (self.name == 'MySQL'):
            self.date = datetime.datetime.strptime(soup.find('div',attrs={'id':'page'}).find_all('p')[0].span.text,"%d %B %Y").strftime("%d-%m-%Y")
            self.news = soup.find('div',attrs={'id':'page'}).find_all('h3')[0].text.strip()
        elif (self.name == 'MariaDB'):
            self.date = datetime.datetime.strptime(soup.find('div',attrs={'class':'well recent_blog_posts'}).find_all('h4')[0].small.text.strip(),"%d %b %Y").strftime("%d-%m-%Y")
            self.news = soup.find('div',attrs={'class':'well recent_blog_posts'}).find_all('h4')[0].a.text.strip()
        elif (self.name == 'MongoDB'):
            self.date = datetime.datetime.strptime(soup.find_all('table',attrs={'class':'table table-hover'})[0].find_all('tr')[1].td.text,"%b %d, %Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('table',attrs={'class':'table table-hover'})[0].find_all('tr')[1].a.text.strip()
        elif (self.name == 'elasticsearch'):
            self.date = datetime.datetime.strptime(soup.find('ul',attrs={'class':'blog-details'}).find_all('li')[0].span.text,"%B %d, %Y").strftime("%d-%m-%Y")
            self.news = soup.find('ul',attrs={'class':'blog-details'}).find_all('li')[0].a.text.split("-")[0]
        elif (self.name == 'OpenSSH'):
            self.date = datetime.datetime.strptime(soup.find_all('li')[0].strong.text,"%B %d, %Y").strftime("%d-%m-%Y")
            self.news = soup.find_all('li')[0].br.next_sibling.strip()
        elif (self.name == 'MediaWiki'):
            self.date = datetime.datetime.strptime(soup.find_all('dl')[0].text.strip(),"%Y-%m-%d").strftime("%d-%m-%Y")
            self.news = soup.find_all('ul')[1].text.strip()
        elif (self.name == 'OpenVAS'):
            aux = soup.find_all('div',attrs={'class':'content'})[0].h3.text.split("-")[0]
            aux_re = re.sub(r"\b([0123]?[0-9])(st|th|nd|rd)\b",r"\1",aux)
            self.date = datetime.datetime.strptime(aux_re,"%B %d, %Y ").strftime("%d-%m-%Y")
            self.news = " ".join(soup.find_all('div',attrs={'class':'content'})[0].h3.text.split("-")[1:])
        elif (self.name == 'Zaproxy'):
            self.date = datetime.datetime.strptime(soup.find_all('li')[0].text.strip().split(" ")[0],"%Y/%m/%d").strftime("%d-%m-%Y")
            self.news = " ".join(soup.find_all('li')[0].text.strip().split(" ")[1:])
        elif (self.name == 'Ruby on rails'):
            self.date = datetime.datetime.strptime(soup.find_all('span',attrs={'class':'published'})[0].get('title'),"%Y-%m-%d %X +0000").strftime("%d-%m-%Y")
            self.news = soup.find_all('h2',attrs={'class':'entry-title'})[0].text.strip()
        elif (self.name == "Joomla"):
            self.date = datetime.datetime.strptime(soup.find_all('time',attrs={'itemprop':'dateCreated'})[0].get('datetime').split('T')[0],'%Y-%m-%d').strftime("%d-%m-%Y")
            self.news = soup.find_all('h2',attrs={'itemprop':'name'})[0].a.text.strip()
        else:
            self.date = None
            self.news = None

    def __repr__(self):
        return repr((self.name, self.date, self.url, self.news))

    def __str__(self):
        return "[*] Name: %s\n[+] Date: %s\n[+] Last News: %s\n[+] URL: %s" % (self.name,
                    self.date, self.news, self.url)


def opciones():
        parser = OptionParser("usage: %prog [options] \nExample: ./%prog -n drupal,django")
        # TODO: parametros -F --format xml,json,csv,...
        parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", help="Verbose")
        parser.add_option("-A", "--all",
                  action="store_true", dest="all", help="All software")
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
                        software_aux = Software(i[0], i[1])
                        software_aux.getData()
                        data_output.append(software_aux)
                    if (options.format == XML):
                        printXML(data_output, options.output)
                    # TODO: Add more formats!
                else:
                    print("[-] Fail: need format output (e.g -f xml)")
            else:
                printAll()
        elif (options.name is not None):
            if (options.output is not None):
                if (options.format is not None):
                    for name in options.name.split(","):
                        addList(name.strip())
                    if (options.format == XML):
                        printXML(data_output, options.output)
                else:
                    print("[-] Fail: need format output (e.g -f xml)")
            else:
                if (len(options.name.split(",")) > 0):
                    for name in options.name.split(","):
                        printNormal(name.strip())
                else:
                    printNormal(options.name)


def getURL(name2find):
    try:
        (name, url) = data[[x[0].upper() for x in data].index(name2find.upper())]
        return (name, url)
    except ValueError:
        return None
    except TypeError:
        return None


def printNormal(name2find):
    try:
        (name, url) = getURL(name2find)
        if url is not None:
            software = Software(name, url)
            software.getData()
            print(software)
        else:
            print("[-] Name %s Not found." % name2find)
    except TypeError:
        print("[-] Name %s Not found." % name2find)


def addList(name2find):
    '''Add data info to the global list'''
    try:
        (name, url) = getURL(name2find)
        if url is not None:
            software = Software(name, url)
            software.getData()
            data_output.append(software)
    except TypeError:
        pass


def printJSON(filename):
    '''TODO'''
    return None


def printAll():
    '''Print all list'''
    for i in data:
        software = Software(i[0], i[1])
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

