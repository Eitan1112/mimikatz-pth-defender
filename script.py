import sys
import win32evtlog
import win32event
import win32api
import win32con
import datetime
import logging
import socket
from pyad import aduser
import subprocess
import re
import threading


logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s', handlers=[logging.FileHandler('script.log'), logging.StreamHandler()])
logger = logging.getLogger()

HOSTNAME = socket.gethostname() + '$'
SERVER = 'localhost'

SOURCE_TYPE = "Security"
FLAGS = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

EVT_WAIT_TIME = 1
PRIOR_EVENTS_SEARCH_SECONDS = 60

EMPTY_EVENT_ATTRIBUTES = None
EMPTY_EVENT_MANUAL_STATE = 1
EMPTY_EVENT_INITIAL_STATE = 0
EMPTY_EVENT_NAME = 'evt0'
READ_EVENT_LOG_OFFSET = 0

LOGON_EVENT_ID = 4624
PTH_LOGON_TYPE = '9'
EMPTY_EVENT_ATTRIBUTE_SIGN = '-'


def handle_new_event():
    """
    Called when a Aanew security event is registered in the Domain Controller (localhost).
    Goes over the latest events, and check for a valid logon event. If found, calls 'check_logon'
    to check the events on the remote server.

    Return Value (NoneType): None
    """
    
    log_handle = win32evtlog.OpenEventLog(SERVER, SOURCE_TYPE) # Open the log file to view the latest event
    events = win32evtlog.ReadEventLog(log_handle, FLAGS, READ_EVENT_LOG_OFFSET) # Read the events from the log file
    time_index = events[0].TimeGenerated # Time of latest event

    for event in events:
        if(event.TimeGenerated != time_index): # Only check new events - 
            return

        if(event.EventID != LOGON_EVENT_ID): 
            continue
        
        account_name = event.StringInserts[5]
        logonType = event.StringInserts[8]
        account_domain = event.StringInserts[18]
        
        if(account_name == HOSTNAME or account_domain == EMPTY_EVENT_ATTRIBUTE_SIGN):
            continue
        
        logger.info(f'{account_name} logged on to {account_domain}. Logon Type: {logonType}. Checking logon in remote computer...')
        threading.Thread(target=handle_remote_actions, args=(account_domain, account_name)).start()


def handle_remote_actions(account_domain, account_name):
    """
    
    """
    
    objects_to_disable = check_logon(account_domain)
    if(not objects_to_disable):
        logger.info(f'{account_name} to {account_domain} - Legitimate logon.')
        return
    (attacking_user, attacked_user) = objects_to_disable
    session_id = get_session_id(attacking_user, account_domain)
    if(session_id):
        logoff_user(session_id, account_domain)
    disable_ad_objects(objects_to_disable)


def disable_ad_objects(objects):
    """
    Disables every object from the list in the active directory.

    Parameters:
    objects names (list): List of objects names to disable

    Return Value (NoneType): None
    """

    for object_name in objects:
        try:
            selected_object = aduser.ADUser.from_cn(object_name)
            selected_object.disable()
            logger.info(f'Disabled {object_name}.')
        except Exception as e:
            logger.warning(f'Unable to disable {object_name}. Error: {e}')


def get_session_id(user, account_domain):
    """
    Gets the Session ID of a user from a remote machine.

    Parameters:
    user (string): Username of the user
    account_domain (string): Ip address of the remote computer

    Return Value:
    If found session id (string): The session ID
    If unable to find session id (NoneType): None
    """

    args = [r'C:\Windows\System32\query.exe', 'session', f'/server:{account_domain}']
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    output, err = process.communicate()
    output = output.decode('utf-8')
    session_id_re = re.search(f'{user}\s+(\d+)', output)
    if(session_id_re):
        session_id = session_id_re[1]
        logger.info(f'User {user} on {account_domain} session id: {session_id}.')
        return str(session_id)
    else:
        logger.warning(f'Unable to find session id of {user} on {account_domain}.')
        return

def logoff_user(session_id, account_domain):
    """
    Logs off a user based on session id from a remote machine.

    Parameters:
    session_id (string): Session id
    account_domain (string): Ip address of the remote machine

    Return Value (Boolean): True if logged the user off, False if unable to log it off.
    """

    args = [r'C:\Windows\System32\logoff.exe', session_id, f'/server:{account_domain}']
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    try:
        output, err = process.communicate(timeout=2)
    except:
        logger.info(f'Unable to log user with SID {session_id} off {account_domain}')
        return False
    output = output.decode('utf-8')
    if('not found' in output):
        logger.info(f'Unable to log user with SID {session_id} off {account_domain}')
        return False
    logger.info(f'Logged user with SID {session_id} off {account_domain}')
    return True


def check_logon(account_domain):
    """
    Called when a valid logon event is registered on the DC (localhost).
    Reads the latest events on the remote computer, and if a logonType=9 event is on the machine,
    there is a PTH attack occuring.

    Parameters:
    account_domain: Ip address of the remote computer.

    Return Value (tuple): (attacking user, attacked user)
    """

    logon_time = datetime.datetime.now()

    try:
        hands = win32evtlog.OpenEventLog(account_domain, SOURCE_TYPE) # Open the log file to view the latest event
    except Excception as e:
        logger.info(f'Unable to contact {account_domain}: {e}')
        return
    
    while True:
        events = win32evtlog.ReadEventLog(hands, FLAGS, 0) # Read the events from the log file
        for event in events:
            if(event.EventID == LOGON_EVENT_ID and event.StringInserts[8] == PTH_LOGON_TYPE):
                logger.info(f'Pass the hash found! Host: {account_domain}. At: {event.TimeGenerated}. Attacking user: {event.StringInserts[5]}. Attacked user: {event.StringInserts[22]}')
                return (event.StringInserts[5], event.StringInserts[22])
            elif(event.EventID == LOGON_EVENT_ID):
                print(event.EventID, event.TimeGenerated, event.StringInserts[8])

            event_time = datetime.datetime(event.TimeGenerated.year, 
            event.TimeGenerated.month, 
            event.TimeGenerated.day, 
            event.TimeGenerated.hour, 
            event.TimeGenerated.minute, 
            event.TimeGenerated.second, 
            event.TimeGenerated.microsecond)

            if(abs(logon_time - event_time).seconds > PRIOR_EVENTS_SEARCH_SECONDS):
                return

        

def main():
    """
    Listens to new Security events on the Domain Controller (localhost).
    For every new logon, the DC will view the latest events of the remote computer trying to logon.
    If there is an event that matches an attack description, quarintine the computer, and disable both the logged on user the the attacked user.

    Return Value (NoneType): None
    """

    log_handle = win32evtlog.OpenEventLog(SERVER, SOURCE_TYPE) # Opens the source_type log from the server
    evt_handle = win32event.CreateEvent(EMPTY_EVENT_ATTRIBUTES, EMPTY_EVENT_MANUAL_STATE, EMPTY_EVENT_INITIAL_STATE, EMPTY_EVENT_NAME) # Creates an empty event
    win32evtlog.NotifyChangeEventLog(log_handle, evt_handle) # Notify changes in h_evt foreach change in h_log
    logger.info(f"Waiting for changes in the '{SOURCE_TYPE}' event log...")
    
    while True:
        wait_result = win32event.WaitForSingleObject(evt_handle, EVT_WAIT_TIME) # Waits for a new object in h_evt
        if wait_result == win32con.WAIT_OBJECT_0: # If there is a new object
            handle_new_event()
                
        elif wait_result == win32con.WAIT_ABANDONED: 
            logger.info("Abandoned")
    win32api.CloseHandle(evt_handle) # Close the event handles
    win32evtlog.CloseEventLog(log_handle) # Close the log file


if(__name__ == '__main__'):
    main()
