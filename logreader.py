import datetime
import logger
import datehandler
import detector
#import broadcast
import time

def loadlogs():
    filename = '/var/log/apache2/access.log'
    # -- removed -- broad = broadcast.Broadcast()
    det = detector.Detector()
    try:
        # Open logs and begin to read.
        f = open(filename, 'r')
        underAttack = False
        #Foreach log in the logs
        for log in f:
            #Get Attributes
            attr = getAttributes(log)
            # If we have examined this in the past skip this record
            if not datehandler.checkvalidity(attr['date'], lastdate):
                continue 
            # Otherwise continue to analyze it
            if det.analyze(attr) == 1:
                underAttack = True
                # break
        
        #If the above skipped we want to get to check this
        try:
            #If logs have been cleared this should fire an exception
            if len(log) == 0:
                logger.intrusionDetected("Intrusion Detected! /var/log/apache2/access.log has been cleared!")
        except UnboundLocalError: # And this should hit!
            logger.intrusionDetected("Intrusion Detected! /var/log/apache2/access.log has been cleared!")
             # -- removed -- broad.notify("Intrusion Detected! /var/log/apache2/access.log has been cleared!")
            #Broadcast API
            exit()


        # If we are not under attack report success
        if not underAttack:
            logger.success("No incidents have been noticed!")
        else:
            # Notify the user that we are under attack
            logger.intrusionDetected("Server Under Attack! Action is REQUIRED!")
            
            # After we are done log the date and time of the last record to run from there the next time.
            datehandler.logdate(attr['date'])
            if det.Max404 > 25:
                logger.important('[Potential Intrusion Detected]    There are {0} consecutive 404 requests. Logging as important!'.format(det.Max404))
                det.threatsdetected.append('[Potential Intrusion Detected]    There are {0} consecutive 404 requests.'.format(det.Max404))

            det.threatsdetected = removeDuplicates(det.threatsdetected)

            print('='*30)
            print('SUMMARY')
            print('='*30)
            print(det.threatsdetected)

             # -- removed -- broad.notify('\n'.join(det.threatsdetected))
        f.close()
        
    except FileNotFoundError:
        #Apache removes by default the files near 12am so we gotta check for that. (Mostly if there's an access.log.1 which is not empty)
        try:
            with open('/var/log/apache2/access.log.1', 'r') as test:
                if not test.read() > 0:
                    logger.intrusionDetected("Intrusion Detected! log files have been deleted!!!")
        	     # -- removed -- broad.notify("Intrusion Detected! log files have been deleted!!!")
        except FileNotFoundError:
            logger.intrusionDetected("Intrusion Detected! log files have been deleted!!!")
             # -- removed -- broad.notify("Intrusion Detected! log files have been deleted!!!")
    except PermissionError:
        logger.important("Please run the script as Superuser!")

def removeDuplicates(x):
    return list(dict.fromkeys(x))

def getAttributes(log):
    parts = log.split(' ')
    dict = {
        'ip':parts[0],
        'date':parts[3][1:],
        'method':parts[5][1:],
        'fileReq':parts[6],
        'flag':parts[7],
        'respondcode':parts[8],
        'agent':parts[-1][:-1]
    }
    
    #for key in dict.keys():
    #    print('{0}:\t{1}'.format(key, dict[key]))
    return dict


lastdate = datehandler.loaddate()

loadlogs()
