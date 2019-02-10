"""
VirusTotal Automated Investigation for LogRhythm
Dan Crossley | daniel.crossley@logrhythm.com
Feb 2019

Version 2.0

This example should be considered a proof of concept only, and does not necessarily represent best practices recommended by LogRhythm.

Usage:  VT-Investigation-SRP.py [-h HASH ] <AlarmID>

Plugin Flow:
 - VT-Investigation-SRP triggered by a LogRhythm alarm. Log must include a hash (ie FIM, DLP etc)
 - VT-Investigation-SRP checks the hash from the alarm against VirtusTotal 
 - If there are greater than THRESHOLD (default = 10) VT detections:
    - Create a LogRhythm case (case external id value is written as the current system time)
    - Write the caseid to file for chained SRPs
    - Attach Alarm to the case (alarm id from calling argument)
    - Annote case with summary of VirusTotal report and link
    - Add Playbook to the case (playbook id defined in VT_PLAYBOOK_ID)
    - Elevate case status to 'Incident'
 - If there are less than THRESHOLD VT detections:
    - Close Alarm

"""

import json
import requests
import sys
import hashlib
from datetime import datetime
import urllib3
import os
import pyodbc #Used for automatically closing the alarm

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Disable certificate validation warnings

'''
Global Variables to be updated
'''
LR_URL = '' #IP of the LogRhythm Platform Manager
API_KEY = '' #VirusTotal API key
THRESHOLD = 10  #Min number of positive scanner results for file, url & domain for file to be considered likely malicious
BEARER_TOKEN = '' #LR API Bearer token for authentication
OUTPUT_PATH = 'C:/Program Files/LogRhythm/LogRhythm System Monitor/VT-SRP/' #Path to read/write the case id for chained SRPs
VT_PLAYBOOK_ID = '' #Playbook ID to add to the case

'''
Alarm_DB values, used to automatically close alarm
'''
DB_SERVER = ''
DB_NAME = ''
DB_USERNAME = ''
DB_PASSWORD = ''

'''
Global Variables 
'''
VT_URL = 'https://www.virustotal.com/vtapi/v2/' #VirusTotal URL
HEADERS = { #Headers required for LogRhythm API calls. Do not modify
    'Content-Type': "application/json",
    'Authorization': "Bearer " + BEARER_TOKEN,
    'cache-control': "no-cache",
    }

def get_filereport(hash):
    """Perform API lookup of given hash on VirusTotal.

    Args:
        hash: filehash string, MD5, SHA1 or SHA256.
    Returns:
        the full VirusTotal report in json format.

    """
    url_suffix = 'file/report'
    params = {'apikey': API_KEY, 'resource': hash}
    response = requests.get(VT_URL + url_suffix, params=params)
    return response.json()

def process_response_code(info):
    """Check the VirusTotal response code to ensure hash exists in its database

    Args:
        info: the full VirusTotal report in json format.
    Returns:
        True if the hash was found in the VirusTotal database. False if not.

    """
    if info["response_code"] == 1: #return true for further processing of results
        print("Item found in VT database, standby for results..")
        return True
    elif info["response_code"] == 0:
        print("Item not found in VT database, exiting..")
        return False
    elif info["response_code"] == -2:
        print("Item currently queued for analysis, check back later..")
        return False
    else:
        print("Unknown VT response code. Response code: ", info["response_code"])
        return False

def process_file_result(info):
    """Processes the Virustotal report.
    
    - This function only called if the has was found on the VirusTotal
    - Prints summary of VirusTotal results to screen
    - Performs threshold check for number of detections.

    Args:
        info: the full VirusTotal report in json format.
    Returns:
        True if the hash had greater than THRESHOLD number of detections on VirusTotal. False if not.

    """
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

def create_case(result, alarmid):
    """Creates a case in LogRhythm.
    
    - This function only called if there are greater than THRESHOLD detections on VirusTotal
    - Writes the caseid to a file specified in OUTPUT_PATH/alarmid for chained SRPs (e.g. C:\Program Files\LogRhythm\LogRhythm System Monitor\VT-SRP\<Alarm ID>\case.txt)

    Args:
        result: the full VirusTotal report in json format.
        alarmid: The ID of the calling alarm
    Returns:
        True the ID of the newly created case.

    """
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

def add_alarm(caseid, alarmid):
    """Adds a LogRhythm alarm to a LogRhythm case.

    Args:
        caseid: ID of the case to add the alarm to.
        alarmid: The ID of the alarm to add to the case.

    """
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/evidence/alarms/"
    payload = "{\n  \"alarmNumbers\": [\n    " + alarmid + "\n  ]\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

def add_case_note(caseid, note):
    """Adds an note to a case.

    Args:
        caseid: ID of the case to add the alarm to.
        note: The note to add to the case.

    """
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/evidence/note/"
    payload = "{\n  \"text\": \"" + note + "\"\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)


def add_playbook(playbookid, caseid):
    """Adds a playbook to a case.

    Args:
        caseid: ID of the case to add the alarm to.
        alarmid: The alarm ID to add to the case.

    """
    print('Adding playbook to case..')
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/playbooks/"
    payload = "{\n  \"id\": \"" + playbookid + "\"\n}"
    requests.request("POST", url, data=payload, headers=HEADERS, verify=False)

def change_case_status(caseid, status):
    """Updates a case status

    - Permissible status codes are:
        1 = Created
        2 = Completed
        3 = Incident
        4 = Mitigated
        5 = Resolved

    Args:
        caseid: ID of the case to be updated.
        status: new status of the case.

    """
    url = "https://" + LR_URL + ":8501/lr-case-api/cases/" + caseid + "/actions/changeStatus/"
    payload = "{\n  \"statusNumber\": " + status + "\n}"
    requests.request("PUT", url, data=payload, headers=HEADERS, verify=False)

def run_smartresponse(info, alarmid):
    """Runs the main VT-SRP actions.

    - Creates a case
    - Adds an alarm to the case
    - Adds the VirusTotal results to the case notes
    - Adds the VirusTotal response playbook to the case
    - Changes the status of the case to 'Incident'

    Args:
        info: the full VirusTotal report in json format.
        alarmid: The ID of the triggering alarm.

    """
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

def close_alarm(alarmid, server, database, username, password):
    """Closes an alarm in LogRhythm

    Args:
        alarmid: ID of the alarm to close.

    """
    cnxn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER='+server+';DATABASE='+database+';UID='+username+';PWD='+ password)
    cursor = cnxn.cursor()
    cursor.execute('UPDATE [dbo].[Alarm] SET [DateUpdated] = GETUTCDATE(), [AlarmStatus] = 0, [LastPersonID] = -999 WHERE [AlarmID] = ' + alarmid + ';')

def sha256sum(filename):
    """Calculates a SHA256 hash of a file

    Args:
        filename: name of file to be hashed.
    Returns:
        SHA256 of the file as a string.

    """
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

def main():
    """Main execution code

    - If given a filename, takes hash of file
    - Checks hash against VT
    - If hash found, call function run_smartresponse
    - If hash was not found or there was less than the THRESHOLD number of detections, close the triggereing alarm

    """
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
                        run_smartresponse(info, alarmid) #Run all response actions
                else:
                    close_alarm(alarmid, DB_SERVER, DB_NAME, DB_USERNAME, DB_PASSWORD) #close the alarm if there are less than 10 detections or the hash was not found in VT
                    exit() #the hash was not found in the VT database
            else:
                print('Usage: ', sys.argv[0], '[-h HASH <AlarmId> | -f FILENAME <AlarmId>]')
                exit()
        else:
            print('Usage: ', sys.argv[0], '[-h HASH <AlarmId> | -f FILENAME <AlarmId>]')

if __name__ == '__main__':
    main()
