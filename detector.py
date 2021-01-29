import logger

class Detector:
    def __init__(self):
        # Filters
        self.AttackList = [
            ['404','Directory Attack'],
            ['gobuster','Directory Mapping with gobuster'],
            ['php', 'php abuse'], #Only applies on servers that do not depend on php. If you depend on php remove it.
            ['nikto','Server enumeration with nikto'],
            ['nmap', 'Network enumeration with nmap']
        ]
        self.MethodsAllowed = ['GET', 'POST'] # Add other methods such as OPTIONS etc if your server depends on them
        self.fileReqBlacklist = ['.php', '.bin', 'cgi-bin', '.sh']
        self.fileReqPayloads = [ 
                ['../','Directory Traversal Attack'], 
                ["function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21",'php invoke revshell (windows)?']
        ]
        self.agentsBlacklist = ['gobuster', 'Nikto', 'nmap']

        #Counters: 
        self.Response404 = 0

        #Reporters:
        self.Max404 = 0
        self.threatsdetected = []


    def analyze(self, log):

        if log == 0:
            return -1
        if self.blacklist(log):
            return True
        else:
            return False

    def blacklist(self, log):
        #intrusion level variable
        intrusion = 0
        #Check for the allowed methods
        for method in self.MethodsAllowed:
            if not (log['method'] in method):
                logger.error('[IP: {0}] Potential Intrusion Detected! This method is blacklisted: {1}!'.format(log['ip'], log['method']))
                self.threatsdetected.append("[IP: {0}]  Disallowed method detected! {1}".format(log['ip'], log['method']))
                intrusion += .7
                break
        #Check for repond codes to report potential server enumeration.
        if log['respondcode'] == '404':
            self.Response404 = self.Response404 + 1
            if self.Response404 > self.Max404:
                self.Max404 = self.Response404
            logger.warning('[IP: {0}]   Requested file does not exist! Response code was 404 and there are {1} consecutive 404s. Logging as a warning. File Requested: {2}'.format(log['ip'], self.Response404, log['fileReq']))
            intrusion += 3
        else:
            self.Response404 = 0
        # Check for blacklisted extentions
        for file in self.fileReqBlacklist:
            if file in log['fileReq']:
                logger.important('[IP: {0}] Requested file is blacklisted! File: {1}'.format(log['ip'], log['fileReq']))
                self.threatsdetected.append('[IP: {0}]  Possible HTTP Enumeration: File with blacklisted extention detected! {1}'.format(log['ip'], log['fileReq']))
                intrusion += 1
                break
        #Check for specific payloads
        for payload in self.fileReqPayloads:
            if payload[0] in log['fileReq']:
                logger.important('[IP: {0}] Payload Detected! Attack Type logged as {1}. Payload: {2}'.format(log['ip'], payload[1], payload[0]))
                self.threatsdetected.append('[CRITICAL REQUIRED ATTENTION] [IP: {0}]     Payload detected: {1} of type {2}'.format(log['ip'], payload[0], payload[1]))
                intrusion += 5
                break
        # Check for blacklisted Agents
        for agent in self.agentsBlacklist:
            if agent in log['agent']:
                logger.important('[IP: {0}] Possible Attack with: {1}'.format(log['ip'], log['agent']))
                self.threatsdetected.append('[IP: {0}]  Blacklisted Agent has been detected: {1}'.format(log['ip'], agent))
                intrusion += 3
                break
        #After all the checks if we have a high level of intrusion we report it. otherwise we skip it
        if intrusion > 1.5 and intrusion < 3:
            return False
            #logger.warning('Possible Intrusion Detected: Level Medium. Log that triggered this: {0}'.format(log))
        elif intrusion >= 3:
            #logger.intrusionDetected('Intrusion Detected: Level Critical. Log that triggered this: {0}'.format(log))
            return True
