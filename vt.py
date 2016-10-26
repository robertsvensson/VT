import requests
import json

class ConnectionHandle(object):

    def __init__(self, apiKey):
        self.apiKey = apiKey

    def getURLreport(self,url):
        result = self.sendURLtoVirusTotal_returnJSON(url)
        return result

    def sendURLtoVirusTotal_returnJSON(self,url):
        virusTotalURL = 'https://www.virustotal.com/vtapi/v2/url/scan'
        payload = {'url': url, 'apikey': self.apiKey}
        r = requests.post(virusTotalURL, params=payload)
        return r.content
