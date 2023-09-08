import VT_API
import pandas as pd
import time


fileSelect = input("Please select file to select for Virus Total lookup:\n")
dataSelect = input("Please select data column from file for Virus Total lookup:\n")
fileData = pd.read_csv(fileSelect, dtype=str)
fileData.dropna(how='all', inplace=True)
allData = list(fileData[dataSelect])
dataSet = set(fileData[dataSelect])
dataList = list(dataSet)
VendorReports = {}
CommunityReputation = {}
countryCodes = {}
for data in dataList:
    VTrequest = VT_API.Request(data, VT_API.APIkey)
    response1, response2 = VTrequest.submit()
    if VTrequest.IDtype == 'IP':
        countryCodes[data] = response1
    elif VTrequest.IDtype == 'File Hash':
        CommunityReputation[data] = response1
    VendorReports[data] = response2
    print('Processing IoC data {} out of {}...'.format(dataList.index(data)+1,len(dataList)))
    time.sleep(30)
resultData = pd.DataFrame(data={'IoC':allData})
VendorReportsList = []
CommunityReputationList = []
countryCodesList = []
i=0
while i<len(allData):
    if allData[i] in VendorReports.keys():
        VendorReportsList.append(VendorReports[allData[i]])
    else:
        VendorReportsList.append('NA')
    if allData[i] in CommunityReputation.keys():
        CommunityReputationList.append(CommunityReputation[allData[i]])
    else:
        CommunityReputationList.append('NA')
    if allData[i] in countryCodes.keys():
        countryCodesList.append(countryCodes[allData[i]])
    else:
        countryCodesList.append('NA')
    i+=1
resultData.insert(1,'Country Code',countryCodesList,True)
resultData.insert(2,'Vendor Malicious reports',VendorReportsList,True)
resultData.insert(3,'Community Reputation',CommunityReputationList,True)
resultData.to_csv('ReputationReports.csv', mode='w')
print("Processing VirusTotal lookup complete.\n")