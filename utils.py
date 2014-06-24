#!/usr/bin/env python
# coding=UTF-8
# Title:       utils
# Description: Contains utilities.
# Author       David Nellessen <david.nellessen@familo.net>
# Date:        4/2/14
# Note:        
#==============================================================================

# Import modules
import re
import urllib
import urlparse
import time
import hashlib
from hashids import Hashids


# Compile the regular expression for validating URLs.
url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def validate_url(url):
    """
    Validates a given URL.

    :see https://github.com/django/django/blob/master/django/core/validators.py#L58
    """
    if url_regex.match(url): return True
    else: return False


def normalize_url(url, charset='utf-8'):
    """Sometimes you get an URL by a user that just isn't a real
    URL because it contains unsafe characters like ' ' and so on.  This
    function can fix some of the problems in a similar way browsers
    handle data entered by the user:

    >>> url_fix(u'http://de.wikipedia.org/wiki/Elf (Begriffsklärung)')
    'http://de.wikipedia.org/wiki/Elf%20%28Begriffskl%C3%A4rung%29'

    :param charset: The target charset for the URL if the url was
                    given as unicode string.

    :see: http://stackoverflow.com/questions/120951/how-can-i-normalize-a-url-in-python
    """
    if isinstance(url, unicode):
        s = url.encode(charset, 'ignore')
    scheme, netloc, path, qs, anchor = urlparse.urlsplit(s)
    path = urllib.quote(path, '/%')
    qs = urllib.quote_plus(qs, ':&=')
    return urlparse.urlunsplit((scheme, netloc, path, qs, anchor))


def generate_hash(redis_connection, redis_namespace=':short', hash_salt=''):
    """
    Generates an URL hash.
    This will increase the hash counter for the current day no mater if the hash will be used or not.
    """
    days_since_epoch = int(time.time() / 86400)
    day_index = redis_connection.incr(redis_namespace + 'HI:' + str(days_since_epoch))
    hashids = Hashids(salt=hash_salt)
    return hashids.encrypt(days_since_epoch, day_index)


def get_hash_from_url(short_url):
    """
    Gets the hash from a short URL which is the path without the trailing slash.
    """
    p = urlparse.urlparse(short_url).path
    assert p[0:1] == '/'
    return p.replace('/', '')

def hash_dict():
    chars = (
        "a","b","c","d","e","f","g","h",
        "i","j","k","l","m","n","o","p",
        "q","r","s","t","u","v","w","x",
        "y","z","0","1","2","3","4","5",
        "6","7","8","9","A","B","C","D",
        "E","F","G","H","I","J","K","L",
        "M","N","O","P","Q","R","S","T",
        "U","V","W","X","Y","Z",
        )

    return chars

def get_hash_from_map(origin):
    """
    You can change this hash string .
    """
    key = "718d26efb2652ce50656fa3046d73960"
    hex = hashlib.md5(key + origin).hexdigest()
    res = [0 for i in range(4)]
    chars = hash_dict()

    for i in range(4):
        hexint = 0x3FFFFFFF & int("0x" + hex[i * 8: i*8+8], 16)
        outChars = ""
        for j in range(6):
            index = 0x0000003D & hexint
            outChars += chars[index]
            hexint = hexint >> 5
        res[i] = outChars
    url_length = len(str(origin))
    position = url_length % 4
    return res[position]