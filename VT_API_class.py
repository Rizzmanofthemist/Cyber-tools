import requests, re, urllib.parse, contextlib, os, json

url = ""
headers = {"accept": "application/json"}
ipv4_regex = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
url_regex = re.compile("^(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256})")
APIkey =  dict(os.environ.items())['VTAPI'].strip("'")

class Request:
    def __init__(self, objectID, apikey):
        if bool(re.match(ipv4_regex, str(objectID))):
            self.IDtype = 'IP'
            api_url = "https://www.virustotal.com/api/v3/ip_addresses/" + str(objectID)
        elif bool(re.match(url_regex, str(objectID))):
            self.IDtype = 'URL'
            url_object = urllib.parse.quote(objectID.encode("utf8"), safe='')
            api_url = "https://www.virustotal.com/api/v3/urls/" + url_object
        else:
            self.IDtype = 'File Hash'
            api_url = "https://www.virustotal.com/api/v3/files/" + str(objectID)
        headers["x-apikey"] = str(apikey)
        self.header = headers
        self.url = api_url
    
    def submit(self):
        self.response = requests.get(self.url, headers=self.header)
        """with open('output.txt', 'w') as o:
            with contextlib.redirect_stdout(o):
                print(self.response.text)"""
        responseJSON = json.loads(self.response.text)
        if self.IDtype == 'IP':
            try:
                CountryCode = responseJSON['data']['attributes']['country']
                VendorReportCount = responseJSON['data']['attributes']["last_analysis_stats"]['malicious']
            except KeyError:
                print('IP address/subnet not in reputation database.\n')
                CountryCode = 'Unknown'
                VendorReportCount = 'NA'
            else:
                CountryCode = responseJSON['data']['attributes']['country']
                VendorReportCount = responseJSON['data']['attributes']["last_analysis_stats"]['malicious']
            output1, output2 = str(CountryCode), str(VendorReportCount)
        elif self.IDtype == 'URL':
            #
            pass
        elif self.IDtype == 'File Hash':
            try:
                VendorReportCount = responseJSON['data']['attributes']["last_analysis_stats"]['malicious']
            except KeyError:
                print('File data not in reputation database.\n')
                VendorReportCount = 'NA'
            else:
                VendorReportCount = responseJSON['data']['attributes']["last_analysis_stats"]['malicious']
            try:
                harmlessCount = int(responseJSON['data']['attributes']['total_votes']['harmless'])
                maliciousCount = int(responseJSON['data']['attributes']['total_votes']['malicious'])
                CommunityReputation = str(round((maliciousCount*100)/(harmlessCount+maliciousCount),2))+'%'
            except ZeroDivisionError:
                print('Invalid community vote values, cannot calculate reputaion percentage.\n')
                CommunityReputation = None
            except KeyError:
                print('Missing JSON object, Community vote data do not exist.\n')
                CommunityReputation = None
            else:
                CommunityReputation = str(round((maliciousCount*100)/(harmlessCount+maliciousCount),2))+'%'            
            output1, output2 = str(CommunityReputation), str(VendorReportCount)
        return output1, output2
