import vt

#   Set your API key
apiKey = '0b6126891ec76d3e72ae4d2973fe2aced829114ed82c9060d5d24d3a6697e6c1'

#   Create an object called con that we will use for all of our communication with virusTotal.com
con = vt.ConnectionHandle(apiKey)

#   Get Virustotal.com report for the specified URL
print con.getURLreport('http://www.dn.se')
