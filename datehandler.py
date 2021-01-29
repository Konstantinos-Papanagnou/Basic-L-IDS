import datetime

def checkvalidity(textdate, lastdate):
    date = parseDate(textdate)
    if date <= lastdate:
        return False
    return True

def parseDate(textdate):
    return datetime.datetime.strptime(textdate, '%d/%b/%Y:%H:%M:%S')
    
def logdate(date):
    with open('~/idslastloggeddate.conf', 'w') as file:
        file.write(date)

def loaddate():
    try:
        with open('~/idslastloggeddate.conf', 'r') as file:
            return parseDate(file.read())
    except FileNotFoundError:
        return datetime.datetime.min
