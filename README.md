pysoftnews
=========

Command line tool to get the latest news from a set of common software.


Intro
-----

This is a tool in continual updating to add the maximum quantity of software.


Usage
-----


```
	[manu@Golgota ~/GitHub/pysoftnews]$ ./pysoftnews.py --help
	Usage: pysoftnews.py [options] 
	Example: ./softNews.py -o filename

	Options:
	  -h, --help            show this help message and exit
	  -A, --all             All software
	  -o OUTPUT, --output=OUTPUT
	                        Filename output
	  -n NAME, --name=NAME  Software name(s)

```

Requeriments
------------

I think that the version is not mandatory

```
requests >= 2.6.2
bleach >= 1.4.1
BeautifulSoup = 4.4.0

```

Hacking
-------

The target is create a good tool with more possible software. 
If you want to add more software is too easy edit this script, but, please, if You update this script do a **pull request** to this project.

Author
------

For the moment:
Manuel Mancera (sinkmanu@gmail.com/[@sinkmanu](https://twitter.com/sinkmanu))

Be free to add your name if you contribute with it.
