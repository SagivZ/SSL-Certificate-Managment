import datetime
import socket
import ssl
import logging

"""
SSL certificate management which automates the process of testing a web server's ability to accept incoming sessions over a secure channel,
and verifying the security certificate's expiration date.
Sagiv Zafrani 
"""

file = open("domains.txt", "r")
for hostname in file:
    hostname = hostname.replace("\n", "")
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    # parse the string from the certificate into a Python datetime object
    expires = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
    print("The Domain %s SSL certificate will expire at %s" % (hostname, expires.isoformat()))
    # if the cert expires in less than two weeks, we should reissue it
    now = datetime.datetime.now()
    remaining = expires - now
    buffer_days = 14
    if remaining < datetime.timedelta(days=0):
        # cert has already expired
        print("The Certificate expired %s days ago" % remaining.days)
    elif remaining < datetime.timedelta(days=buffer_days):
        # cert expires sooner than the buffer
        print("The Certificate will expire %s more days" % remaining.days)
    else:
        # everything is fine
        print("The Certificate is valid for use and will expire %s more days" % remaining.days)
