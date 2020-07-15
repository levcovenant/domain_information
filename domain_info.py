#!/usr/bin/python3

# Required Modules:
# 1) dnspython3
# 2) termcolor
# 3) pythonwhois

# pip install dnspython termcolor git+https://github.com/levcovenant/python-whois.git click

import dns.resolver
import dns.reversename
import pythonwhois
from termcolor import colored

import click


def whois(domain_name):
    # Get Whois Data
    w = pythonwhois.get_whois(domain_name)
    # Get Registrar Data
    try:
        Registrar = w['registrar']
        print("The Registrar of %s is: %s" % (domain_name, Registrar))
    except:
        print("No Known Registrar For %s" % domain_name)
    # Get Expiration Date of Domain.
    try:
        eDate = ' '.join(str(x) for x in w['expiration_date'])
        print("The Expiration Date of %s is %s" % (domain_name,eDate))
    except Exception as e:
        print("Domain %s has no expiry date" % domain_name)
    # Get Domain Status
    try:
        Domain_Status = w['status']
        print("The Status of %s is: %s" % (domain_name, Domain_Status))
    except:
        print("No Status for %s " % domain_name)
    # Get Domain NameServers
    try:
        NameServersOfDomain = w['nameservers']
        print("The NameServers of %s are: %s" % (domain_name, NameServersOfDomain))
    except:
        print("No Nameservers for %s " % domain_name)


def dominfo(domain_name, ns_server_ip, record):
    myResolver = dns.resolver.Resolver()
    myResolver.nameservers = [ns_server_ip]
    serv_name = ''
    reversed_dns1 = ''
    if ns_server_ip == '8.8.8.8':
        serv_name = 'Google Dns'
    elif ns_server_ip == '80.244.161.84':
        serv_name = 'ns1.sitesdepot.com'
    elif ns_server_ip == '80.244.160.50':
        serv_name = 'ns2.sitesdepot.com'
    try:
        myAnswers = myResolver.query(domain_name, str(record))
        for rdata in myAnswers:
            if serv_name == '':
                print("%s record/s of %s in %s is %s " % (record, domain_name, ns_server_ip, rdata))
            else:
                print("%s record/s of %s in %s is %s " % (record, domain_name, serv_name, rdata))
            if record == 'MX' or record == 'mx':
                myAnswers2 = myResolver.query(rdata.exchange, 'A')
                for MxIp in myAnswers2:
                    try:
                        rev_name = dns.reversename.from_address(str(MxIp))
                        reversed_dns1 = str(dns.resolver.query(rev_name, "PTR")[0])
                    except:
                        pass
                    print("The A record of %s is %s and its PTR is %s" % (rdata.exchange, MxIp, reversed_dns1))
    except Exception as e:
        print(e)


@click.command()
@click.option('--domain', required=True, help='domain name to query')
@click.option('--who', is_flag=True, help='whois data only')
@click.option('--ns', help='IP of ns server')
def domain_info(domain, who, ns):
    """ Simple Whois + Dig Cli Tool """
    if who:
        Whois_Head = colored('Whois Information:', 'red')
        click.echo(Whois_Head)
        whois(domain)
    elif ns:
        dominfo(domain, ns, 'A')
        dominfo(domain, ns, 'MX')
        dominfo(domain, ns, 'TXT')
    else:
        Whois_Head = colored('Whois Information:', 'red')
        click.echo(Whois_Head)
        whois(domain)
        GHeadLine = colored('Google DNS Information:', 'red')
        click.echo(GHeadLine)
        dominfo(domain, '8.8.8.8', 'A')
        dominfo(domain, '8.8.8.8', 'MX')
        dominfo(domain, '8.8.8.8', 'TXT')
        DHeadLine = colored('Interspace DNS Information:', 'red')
        click.echo(DHeadLine)
        dominfo(domain, '80.244.161.84', 'A')
        dominfo(domain, '80.244.160.50', 'A')
        dominfo(domain, '80.244.161.84', 'MX')
        dominfo(domain, '80.244.160.50', 'MX')
        dominfo(domain, '80.244.161.84', 'TXT')
        dominfo(domain, '80.244.160.50', 'TXT')


if __name__ == '__main__':
    domain_info()
