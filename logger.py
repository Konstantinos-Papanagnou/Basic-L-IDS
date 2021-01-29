import datetime
import os

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#log level warning.
loglevel = 2 # 0 Info 1 Warning 2 Error 3 Important 4 Critical

def error(message):
    print(f"{bcolors.FAIL}[-]   {message}{bcolors.ENDC}")
    if loglevel <= 2:
        log(message, 2)

def important(message):
    print(f"{bcolors.UNDERLINE}[!]  {message}{bcolors.ENDC}")
    if loglevel <= 3:
        log(message, 3)

def warning(message):
    print(f"{bcolors.WARNING}[*]    {message}{bcolors.ENDC}")
    if loglevel <= 1:
        log(message, 1)

def success(message):
    print(f"{bcolors.OKGREEN}[+]    {message}{bcolors.ENDC}")
    if loglevel <= 0:
        log(message, 0)

def header(message):
    print(f"{bcolors.OKBLUE}{message}{bcolors.ENDC}")

def intrusionDetected(message):
    print(f"{bcolors.UNDERLINE}{bcolors.FAIL}[INTRUSION ALERT]  {message}{bcolors.ENDC}")
    log(message, 4)

def log(message, severity):
    
    try:        
        os.mkdir('/var/log/IDS')
    except OSError:
        pass

    with open('/var/log/IDS/alert.log', 'a') as file:
        file.write('[{0}] Severity: {1}, {2}\n'.format(datetime.datetime.now(), severity, message))