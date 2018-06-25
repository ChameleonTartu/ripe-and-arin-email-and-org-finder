#!/usr/bin/python3

import pandas as pd
import socket
import json
from urllib import request
import logging
import sys
from _curses import meta

# IO to XLSX file
def read_xlsx(filename, sheet_name):
    data = pd.read_excel(filename, sheet_name=sheet_name)
    data = data.reset_index(drop=True)
    return data

def write_xlsx(data, filename, sheet_name):
    writer = pd.ExcelWriter(filename, engine='xlsxwriter')
    data.to_excel(writer, sheet_name=sheet_name, index=False)
    writer.save()
    return

# Processing of URLs
def parse_url(url):
    sep_index = url.find("://")
    if sep_index != -1:
        url = url[sep_index + 3:] 
    
    slash_pos = url.find("/")
    if slash_pos != -1:
        url = url[:slash_pos]
    
    port_pos = url.find(":")
    if port_pos != -1:
        url = url[:port_pos]
    return url

def nslookup(host):
    dns = socket.gethostbyname(host)
    if dns is None:
        print("NSLOOKUP failed for: ", host)
        return host
    return dns

class WhoisLookup(object):
    
    @staticmethod
    def extract_metadata(ip):
        print("IP {0}".format(ip))
        
        org_ripe, email_ripe = WhoisLookup._extract_metadata_for_ripe(ip)
        org_arin, email_arin = WhoisLookup._extract_metadata_for_arin(ip)
        
        print("RIPE: {0}, {1}".format(org_ripe, email_ripe))
        print("ARIN: {0}, {1}".format(org_arin, email_arin))
        
        org, email = WhoisLookup.__org_and_email_resolver((org_ripe, email_ripe), (org_arin, email_arin))
        return org, email
    
    @staticmethod
    def __org_and_email_resolver(ripe, arin):
        if ripe[1] != '':
            return ripe
        return arin
    
    @staticmethod
    def _extract_metadata_for_arin(ip):
        metadata = None
        try:
            ARIN_URL = "http://whois.arin.net/rest/ip/" + ip
            headers = {"Accept": "application/json"}
            req = request.Request(ARIN_URL, headers=headers)
            metadata = json.loads(request.urlopen(req).read().decode())
        except Exception as e:
            logging.exception("IP lookup in ARIN DB has failed.", e)

        org = WhoisLookup.__extract_org_for_arin(metadata)
        email = WhoisLookup.__extract_email_for_arin(metadata)
        return org, email
    
    @staticmethod
    def __extract_org_for_arin(metadata):
        if metadata is None:
            return ""
        
        org = ""
        if 'net' in metadata and 'orgRef' in metadata['net'] and '@name' in metadata['net']['orgRef']:
            org = metadata['net']['orgRef']['@name']
        return org
    
    @staticmethod
    def __extract_email_for_arin(metadata):
        if metadata is None:
            return ""
        
        email = ""
        if 'net' in metadata and 'parentNetRef' in metadata['net'] and '@handle' in metadata['net']['parentNetRef']:
            handle = metadata['net']['parentNetRef']['@handle']
            try:
                url = "https://whois.arin.net/rest/net/{0}/org/pocs".format(handle)
                headers = {"Accept": "application/json"}
                req = request.Request(url, headers=headers)
                metadata = json.loads(request.urlopen(req).read().decode())
                
                if 'pocs' in metadata and 'pocLinkRef' in metadata['pocs']:
                    abuse_contact_url = None
                    for poc in metadata['pocs']['pocLinkRef']:
                        if '@description' in poc and '@handle' in poc and poc['@description'] == 'Abuse':
                            handle = poc['@handle']
                            abuse_contact_url = "https://whois.arin.net/rest/poc/{0}".format(handle)
                            print("Abuse contact url", abuse_contact_url)
                            break
                    email = WhoisLookup.__extract_email_for_arin_from_abuse_url(abuse_contact_url)
            except Exception as e:
                logging.exception("Extraction email for ARIN has failed", e)
            
        return email
    
    @staticmethod
    def __extract_email_for_arin_from_abuse_url(abuse_contact_url):
        org = ""
        try:
            headers = {'Accept': 'application/json'}
            req = request.Request(abuse_contact_url, headers=headers)
            metadata = json.loads(request.urlopen(req).read().decode())
            if 'poc' in metadata and 'emails' in metadata['poc'] and \
               'email' in metadata['poc']['emails'] and '$' in metadata['poc']['emails']['email']:
                org = metadata['poc']['emails']['email']['$']
        except Exception as e:
            logging.exception("Extraction abuse contact from abuse contact URL has failed", e)
        return org
    
    @staticmethod
    def _extract_metadata_for_ripe(ip):
        RIPE_UI_URL = "https://apps.db.ripe.net/db-web-ui/api/whois/search?abuse-contact=true&flags=B&ignore404=true&managed-attributes=true&resource-holder=true&query-string="
        SOURCE_APP_ID = "sourceapp=investigation007"
        
        url = "&".join([RIPE_UI_URL + ip, SOURCE_APP_ID])
        metadata = None
        try:
            metadata = json.loads(request.urlopen(url).read())
        except Exception as e:
            logging.exception("IP lookup in RIPE DB has failed.", e)
    
        org = WhoisLookup.__extract_org_for_ripe(metadata)
        email = WhoisLookup.__extract_email_for_ripe(metadata)
        return org, email
    
    @staticmethod
    def __extract_org_for_ripe(metadata):
        if metadata is None:
            return ""
        
        org = ""
        for obj in metadata['objects']['object']:
            if obj['type'] == 'inetnum' and 'resource-holder' in obj and 'name' in obj['resource-holder']:
                abuse_contact = obj['resource-holder']
                org = abuse_contact['name']
                break
        return org
        
    @staticmethod
    def __extract_email_for_ripe(metadata):
        if metadata is None:
            return ""
        
        email = ""
        for obj in metadata['objects']['object']:
            if obj['type'] == 'inetnum' and 'abuse-contact' in obj and 'email' in obj['abuse-contact']:
                abuse_contact = obj['abuse-contact']
                email = abuse_contact['email']
        return email
        
def update_table(data):
    VIDEO_URL, EMAILS, ORGANIZATION, IP = 'Video URL', 'Abuse contact', 'Responsible Org', 'DNS IP'
    if IP in data:
        data.drop([IP], inplace=True, axis=1)
    data[IP] = ""
    
    df = pd.DataFrame(columns=data.columns)
    for index, row in data.iterrows():
        url_for_lookup = parse_url(row[VIDEO_URL])
        ip = nslookup(url_for_lookup)        
        org, email = WhoisLookup.extract_metadata(ip)

        row[EMAILS] = email
        row[ORGANIZATION] = org
        row[IP] = ip
        df.loc[index + 1] = row
    return df


if __name__ == '__main__':
    filename = 'myworkbook.xlsx'
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        
    sheet_name = 'INVESTIGATION'
    if len(sys.argv) > 2:
        sheet_name = sys.argv[2]
    
    data = read_xlsx(filename, sheet_name)
    data = update_table(data)
    write_xlsx(data, filename, sheet_name)

