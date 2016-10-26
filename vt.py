import requests
import json

class ConnectionHandle(object):

    def __init__(self, apiKey):
        self.apiKey = apiKey

    def getURLreport(self,url):
        result = self.sendURLtoVirusTotal_returnJSON(url)
        return result

    def sendURLtoVirusTotal_returnJSON(self,url):
        try:
            virusTotalURL = 'https://www.virustotal.com/vtapi/v2/url/scan'
            payload = {'url': url, 'apikey': self.apiKey}
            r = requests.post(virusTotalURL, params=payload)
            return r.content
        except Exception as e:
            print 'Something when very wrong: %s' % (e)

    def getSHA256report(self,sha256):
        result = self.sendSHA256sumToVirusTotal_returnJSON(sha256)
        return result

    def sendSHA256sumToVirusTotal_returnJSON(self,sha256):
        try:
            virusTotalURL = 'https://www.virustotal.com/vtapi/v2/file/report'
            payload = {'resource':sha256,'apikey':self.apiKey}
            r = requests.post(virusTotalURL,params = payload)
            return r.content

        except Exception as e:
            print 'Something went wrong: %s' % (e)
