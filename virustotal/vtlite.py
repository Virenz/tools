#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity
# If things are broken let me know chris@xenosec.org
# No Licence or warranty expressed or implied, use however you wish! 

import json, urllib, urllib2, argparse, hashlib, re, sys, time, Tkinter
from pprint import pprint

class vtAPI():
    def __init__(self):
        self.api = '63efab1f4d9bd879a836a9a38917d89265aedb261ea334df9637fef108512821'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/report"
        data = urllib.urlencode(param)

        while  True:
          try:  
            result = urllib2.urlopen(url,data,timeout = 60)
            status_code = result.getcode()
            print status_code
            if status_code == 200:
              resultjson = result.read()
              jdata =  json.loads(resultjson)
              result.close()
              return jdata
            else:
              result.close()
              time.sleep(10)
          except Exception, e:  
            print e
            time.sleep(10)
    
    def rescan(self,md5):
        param = {'resource':md5,'apikey':self.api}
        url = self.base + "file/rescan"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        print "\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)"


# Md5 Function

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 
          
def parse(it, verbose, jsondump, ftxt):
  index = 0
  ittag = isinstance(it, list)
  if ittag == True:
    for repcode in it:
      index += 1
      virusstr = '%2d -- %s \t ' % (index, repcode['resource'])
      ftxt.write(virusstr)
      if repcode['response_code'] == 0:
        virusstr = '%s\n' % ('Not Found')
        ftxt.write(virusstr)
        #print '\n\tResults for MD5: ',repcode['resource'] ,'\t Not Found'
      else:
        virusstr = 'Detected by: %s / %s\n' % (repcode['positives'], repcode['total'])
        ftxt.write(virusstr)
        #print "\n\tResults for MD5: ",repcode['resource'] ,"\t Detected by: ",repcode['positives'],'/',repcode['total'],'\n'
        # for scanstr in repcode['scans']:
        #   if repcode['scans'][scanstr]['detected'] == True:
        #     virusscan = '\t\t %20s \t %20s\n' % (scanstr, repcode['scans'][scanstr]['result'])
        #     ftxt.write(virusscan)
  else:
    index += 1
    virusstr = '%2d -- %s \t ' % (index, it['resource'])
    ftxt.write(virusstr)
    if it['response_code'] == 0:
        virusstr = '%s\n' % ('Not Found')
        ftxt.write(virusstr)
    else:
      virusstr = 'Detected by: %s / %s\n' % (it['positives'], it['total'])
      ftxt.write(virusstr)
      # for scanstr in it['scans']:
      #   if it['scans'][scanstr]['detected'] == True:
      #     virusscan = '\t\t %20s \t %20s\n' % (scanstr, it['scans'][scanstr]['result'])
      #     ftxt.write(virusscan)

def main():

  fsrc = open(sys.argv[1],'rb')

  x = time.localtime(time.time())
  timestr = time.strftime('---------------%Y-%m-%d %H:%M:%S-------------- \n',x)

  ftxt = open('log.txt' ,'a')
  ftxt.write(timestr)

  filestrs = fsrc.read()
  liststrs = filestrs.split('\n')
  sha1list = ''
  print len(liststrs)
  for x in liststrs:
    if x.strip() != '':
      sha1list += (x.strip() + ', ')
  sha1list = sha1list[:-2]
  print sha1list

  vt=vtAPI()
  parse(vt.getReport(sha1list), True, True, ftxt)

if __name__ == '__main__':
    main()
