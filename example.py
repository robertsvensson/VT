import vt

#   Set your API key
apiKey = 'yourAPIkey'

#   Create an object called con that we will use for all of our communication with virusTotal.com
con = vt.ConnectionHandle(apiKey)

#   Get Virustotal.com report in JSON format for a certain URL.
print con.getURLreport('http://www.dn.se')

#   Get Virustotal.com report in JSON format for a file's SHA256 hash.
print con.getSHA256report('ef794b9a3b72ae5524e17ecccf330eb16f2cc74f3e7fe7cb2667acefdea4b3a3')

#   Send file to Virustotal.com and get the result in JSON format.
#   The method argument 'evil.file' is the path and file name of the file to be scanned.
print con.sendFileToVirusTotal('evil.file')
