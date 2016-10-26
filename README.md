# VT

import vt

#   Set your API key
apiKey = '0b6126891ec76d3e72ae4d2973fe2aced829114ed82c9060d5d24d3a6697e6c1'

#   Create an object called con that we will use for all of our communication with virusTotal.com
con = vt.ConnectionHandle(apiKey)

#   Get Virustotal.com report in JSON format for a certain URL.
print con.getURLreport('http://www.dn.se')

#   Get Virustotal.com report  JSON format for a file's SHA256 hash.
print con.getSHA256report('ef794b9a3b72ae5524e17ecccf330eb16f2cc74f3e7fe7cb2667acefdea4b3a3')
