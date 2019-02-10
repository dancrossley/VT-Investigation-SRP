"""
VirusTotal Automated Investigation for LogRhythm
Dan Crossley | daniel.crossley@logrhythm.com
Feb 2019

Usage:  VT-SRP_v1.py [-h HASH ] <AlarmID>

Actions Taken:
 - SRP triggered by a LogRhythm alarm
 - Checks a hash against VirtusTotal 
 - If there are greater than THRESHOLD (default = 10) VT detections:
    - Create a LogRhythm case (case external id is the system time)
    - Write the caseid to file for chained SRPs
    - Attach Alarm to the case (alarm id from calling argument)
    - Annote case with summary of VirusTotal report and link
    - Add Playbook to the case (playbook id defined in VT_PLAYBOOK_ID)
    - Elevate case status to 'Incident'
 - If there are less than THRESHOLD VT detections:
    - Close Alarm (TO BE IMPLEMENTED)
 
 To Do:
  - Error checking

"""

import json
import requests
import sys
import hashlib
from datetime import datetime
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Disable certificate validation warnings

'''
Global Variables
'''
LR_URL = '' #IP of the LogRhythm Platform Manager
API_KEY = '' #VirusTotal API key
VT_URL = 'https://www.virustotal.com/vtapi/v2/' #VirusTotal URL
THRESHOLD = 10  #Min number of positive scanner results for file, url & domain for file to be considered likely malicious
BEARER_TOKEN = '' #LR API Bearer token for authentication
OUTPUT_PATH = 'C:/Program Files/LogRhythm/LogRhythm System Monitor/VT-SRP/' #Path to read/write the case id for chained SRPs
VT_PLAYBOOK_ID = '' #Playbook ID to add to the case
HEADERS = { #Headers required for LogRhythm API calls. Do not modify
    'Content-Type': "application/json",
    'Authorization': "Bearer " + BEARER_TOKEN,
    'cache-control': "no-cache",
    }

'''
Function Name: get_filereport
- Perform API lookup of given hash on VirusTotal
'''
def get_filereport(hash):
    url_suffix = 'file/report'
    params = {'apikey': API_KEY, 'resource': hash}
    response = requests.get(VT_URL + url_suffix, params=params)
    return response.json()

'''
Function Name: process_response_code
- Check the VirusTotal response code to ensure hash exists in its database
'''
def process_response_code(info):
    if info["response_code"] == 1: #return true for further processing of results
        print("Item found in VT database, standby for results..")
        return True
    elif info["response_code"] == 0:
        print("Item not found in VT database, exiting..")
        exit()
    elif info["response_code"] == -2:
        print("Item currently queued for analysis, check back later..")
        exit()
    else:
        print("Unknown VT response code. Response code: ", info["response_code"])
        exit()

'''
Function Name: process_file_result
- Reads the VirusTotal json report
- Performs threshold check for number of detections
- Prints summary results to screen
'''
def process_file_result(info):
    #print(json.dumps(info, indent=4)) #Uncomment to print full VT report in json format
    positives = info["positives"]
    total = info["total"]
    print("md5:", info["md5"])
    print("sha1: ", info["sha1"])
    print("sha256", info["sha256"])
    print("VT Link:", info["permalink"])
    if positives >= THRESHOLD:
        print("***VT RESULT***: File is likely MALICIOUS with", positives, "detections from", total, "scanners")
        return True #Automatically create an LR case if number of detections is greater than threshold
    elif positives < 10 and positives > 5:
        print("***VT RESULT***: File has some detections with", positives, "convictions from", total, "scanners")
        return False
    elif positives < 5:
        print("***VT RESULT***: File has some detections with", positives, "convictions from", total, "scanners")
        return False

'''
Function Name: create_case
- Create a case based on the VirusTotal results
- Write the new caseid to a file for chained SRPs 
'''
def create_case(result, alarmid):
    print('Automatically creating LogRhythm case..')
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/"
    externalid = str(datetime.now())
    name = 'Malicious File Detected'
    priority = '1'
    summary = 'VirusTotal Detection ' + result["md5"]
    payload = "{\n  \"externalId\": \"" + externalid + "\",\n  \"name\": \"" + name + "\",\n  \"priority\": " + priority + ",\n  \"summary\": \"" + summary + "\"\n}"
    response = requests.request("POST", url, data=payload, headers=HEADERS, verify=False)
    info = response.json()
    caseid = info["id"] #get identifier for case
    print('LogRhythm case created, case id: ' + caseid)
    #Write caseid to a file for chained SRPs
    directory = os.path.join(OUTPUT_PATH, alarmid)
    if not os.path.exists(directory):
        os.makedirs(directory)
    fullpath = os.path.join(directory, 'case.txt')
    fout = open(fullpath, 'w')
    fout.write(caseid)
    return caseid
    
'''
Function Name: add_alarm
 - Adds the given alarm to the given case
'''
def add_alarm(caseid, alarmid):
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/evidence/alarms/"
    payload = "{\n  \"alarmNumbers\": [\n    " + alarmid + "\n  ]\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

'''
Function Name: add_case_note
- Adds the given note to the given case
'''
def add_case_note(caseid, note):
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/evidence/note/"
    payload = "{\n  \"text\": \"" + note + "\"\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

'''
Function Name: add_playbook
- Adds the given playbook to the given case
'''
def add_playbook(playbookid, caseid):
    print('Adding playbook to case..')
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/playbooks/"
    payload = "{\n  \"id\": \"" + playbookid + "\"\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

'''
Function Name: change_case_status
- Updates the case status according to the status codes:
    1 = Created
    2 = Completed
    3 = Incident
    4 = Mitigated
    5 = Resolved
'''
def change_case_status(caseid, status):
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/actions/changeStatus/"
    payload = "{\n  \"statusNumber\": " + status + "\n}"
    requests.request("PUT", url, data=payload, headers=HEADERS, verify=False)

'''
Function Name: run_response
- Creates a case
- Adds an alarm to the case
- Adds the VirusTotal results to the case notes
- Adds the VirusTotal response playbook to the case
'''
def run_response(info, alarmid):
    caseid = create_case(info, alarmid)
    add_alarm(caseid, alarmid)
    note = "***VT RESULT***: File is likely MALICIOUS with " + str(info["positives"]) + " detections from " + str(info["total"]) + " scanners."
    note += ". md5:" + info["md5"]
    note += ". sha1: " + info["sha1"]
    note += ". sha256" + info["sha256"]
    note += ". VT Link:" + info["permalink"]
    add_case_note(caseid, note)
    add_playbook(VT_PLAYBOOK_ID, caseid)
    change_case_status(caseid, '3') #Change case status to Incident   

'''
Function Name: sha256sum
- Returns a SHA256 hash based on a file
'''
def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

'''
Main execution code
'''
def main():
        if len(sys.argv) == 4:
            alarmid = sys.argv[3]
            if sys.argv[1] == '-file' or sys.argv[1] == '-f': #If given a filename, calculate the hash. Can only be used on same machine as SRP is running 
                filename = sys.argv[2]
                if (len(filename) < 1):
                    print('Must be a valid filename')
                    exit()
                else:
                    hash = sha256sum(filename)
            elif sys.argv[1] == '-hash' or sys.argv[1] == '-h':
                hash = sys.argv[2]
                if (len(hash) < 1):
                    print('Must be a valid hash')
                    exit()
                info = get_filereport(hash)    #Get VT report for this hash
                if(process_response_code(info)): #If the hash exists in VT database
                    if(process_file_result(info)): #If hash looks to be malicous
                        run_response(info, alarmid) #Run all response actions
            else:
                print('Usage: ', sys.argv[0], '[-h HASH <AlarmId> | -f FILENAME <AlarmId>]')
                exit()
        else:
            print('Usage: ', sys.argv[0], '[-h HASH <AlarmId> | -f FILENAME <AlarmId>]')


if __name__ == '__main__':
    main()
