pysoftnews
=========

Command line tool to get the latest news from a set of common software.


Intro
-----

This is a tool in continual updating to add the maximum quantity of software.


Usage
-----


```
$ ./pysoftnews.py 
Usage: pysoftnews.py [options] 
Example: ./pysoftnews.py -n drupal,django

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose
  -d, --debug           Debug
  -A, --all             All software
  -t TYPE, --type=TYPE  News type (news, security)
  -f FORMAT, --format=FORMAT
                        Output format
  -o OUTPUT, --output=OUTPUT
                        Filename output
  -n NAME, --name=NAME  Software name(s)
```

Requirements
------------

I think that the version is not mandatory

```
requests >= 2.6.2
bleach >= 1.4.1
BeautifulSoup = 4.4.0
```

Hacking
-------

The target is create a good tool with more possible software. <br />
If you want to add more software is too easy edit this script, but, please, if You update this script do a **pull request** to this project.

Author
------

For the moment:<br />
Manuel Mancera (sinkmanu@gmail.com/[@sinkmanu](https://twitter.com/sinkmanu))<br />
<br />
Be free to add your name if you contribute with it.
