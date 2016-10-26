# VT

VT is a lightweight module for interacting with Virustotal.com
Every valid response is returned by the module as JSON.

# Initial setup
First, import the VT module and configure it to your own virus total API key:
import vt
apiKey = 'yourAPIkey'

#Example usage
##   Create an object called con that we will use for all of our communication with virusTotal.com
con = vt.ConnectionHandle(apiKey)

##   Get Virustotal.com report in JSON format for a certain URL.
print con.getURLreport('http://www.dn.se')
Output:
{"permalink": "https://www.virustotal.com/url/400599c00ee2ddfd4b4d3cd00345b19128b88706292a92bf53f4f4ef618bf2f7/analysis/1477488602/", "resource": "http://www.dn.se/", "url":...and so on

##   Get Virustotal.com report  JSON format for a file's SHA256 hash.
print con.getSHA256report('ef794b9a3b72ae5524e17ecccf330eb16f2cc74f3e7fe7cb2667acefdea4b3a3')

Output:
{"scans": {"Bkav": {"detected": true, "version": "1.3.0.8455", "result": "W32.Cloda4b.Trojan.4a55", "update": "20161026"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Gen:Trojan.Heur.fmKfXCDIycnj", "update": "20161026"}, "nProtect": {"detected": false, "version": "2016-10-26.02", "result": null, "update": "20161026"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20161026"}, "CAT-QuickHeal"........and so on
