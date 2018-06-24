import pandas as pd
import socket
import json
import urllib.request
from pprint import pprint


def read_xlsx(filename, sheet_name='INVESTIGATION'):
    data = pd.read_excel(filename, sheet_name=sheet_name)
    data = data.reset_index(drop=True)
    return data

def parse_url(url):
    if url.startswith("http://"):
        url = url[7:] 
    if url.startswith("https://"):
        url = url[8:]
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
        # pprint(metadata)
    except Exception as e:
        print("Something failed", e)

    email = extract_email(metadata)
    org = extract_org(metadata)
    
    return org, email

def extract_org(metadata):
    if metadata is None:
        return ""
    
    org = ""
    for object in metadata['objects']['object']:
        if object['type'] == 'inetnum' and 'resource-holder' in object and 'name' in object['resource-holder']:
            abuse_contact = object['resource-holder']
            org = abuse_contact['name']
            break
    return org
    
def extract_email(metadata):
    if metadata is None:
        return ""
    
    email = ""
    for object in metadata['objects']['object']:
        if object['type'] == 'inetnum' and 'abuse-contact' in object and 'email' in object['abuse-contact']:
            abuse_contact = object['abuse-contact']
            email = abuse_contact['email']
    return email
    
def update_table(data):
    VIDEO_URL, EMAILS, ORGANIZATION = 'Video URL', 'Abuse contact', 'Responsible Org'
    df = pd.DataFrame(columns=data.columns)
    for index, row in data.iterrows():
        url_for_lookup = parse_url(row[VIDEO_URL])
        ip = nslookup(url_for_lookup)        
        org, email = extract_metadata(ip)

        print(org, email)
        row[EMAILS] = email
        row[ORGANIZATION] = org
        df.loc[index + 1] = row
    return df

def write_xlsx(data, filename, sheet_name='INVESTIGATION'):
    writer = pd.ExcelWriter(filename, engine='xlsxwriter')
    data.to_excel(writer, sheet_name=sheet_name, index=False)
    writer.save()
    return

if __name__ == '__main__':
    filename = 'myworkbook.xlsx'
    data = read_xlsx(filename)
    data = update_table(data)
    write_xlsx(data, filename)
