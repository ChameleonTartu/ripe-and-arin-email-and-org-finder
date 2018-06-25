#!/usr/bin/python3

import pandas as pd
import socket
import json
import urllib.request
import logging
import sys


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
    return url

def nslookup(host):
    dns = socket.gethostbyname(host)
    if dns is None:
        print("NSLOOKUP failed for: ", host)
        return host
    return dns

def extract_metadata(ip):
    RIPE_UI_URL = "https://apps.db.ripe.net/db-web-ui/api/whois/search?abuse-contact=true&flags=B&ignore404=true&managed-attributes=true&resource-holder=true&query-string="
    SOURCE_APP_ID = "sourceapp=investigation007"

    print("IP {0}".format(ip))

    url = "&".join([RIPE_UI_URL + ip, SOURCE_APP_ID])
    metadata = None
    try:
        metadata = json.loads(urllib.request.urlopen(url).read())
    except Exception as e:
        logging.exception("IP lookup has failed.", e)

    email = extract_email(metadata)
    org = extract_org(metadata)
    
    return org, email

def extract_org(metadata):
    if metadata is None:
        return ""
    
    org = ""
    for obj in metadata['objects']['object']:
        if obj['type'] == 'inetnum' and 'resource-holder' in obj and 'name' in obj['resource-holder']:
            abuse_contact = obj['resource-holder']
            org = abuse_contact['name']
            break
    return org
    
def extract_email(metadata):
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
        org, email = extract_metadata(ip)

        print(org, email)
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

