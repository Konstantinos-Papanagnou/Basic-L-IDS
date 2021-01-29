# Basic L-IDS
 Basic Log Intrusion Detection System for Apache2 servers running on Linux

# Configure for your own server.
### **Adviced**
Take a look at your server logs and check for weird requests. Mark them as attacks in your head.
After having a good idea of what you consider an attack/enumeration you can edit the detector.py script to add your own blacklists/whitelists.

# Setup:
Add the script inside a home directory you will run it from. 

### **Important** 
Make sure the permissions on all the scripts and the folder containing the scripts is 600. chmod -r 600 Basic-L-IDS/

In order to fire up the script you need to execute python3 logreader.py
This will fire up the script

### **Note**
The script requires root permissions to execute because it is reading the logs from /var/log
You should be able to change the permissions of apache2 logs to the current user but it is not recommended.
The best way to run the script is as root.

In order to have the script run all at an interval you should add it as a cronjob (TESTED) on /etc/crontab
*/x * * * * root /bin/python3 /path/to/your/script/logreader.py

This will automatically create log files inside /var/log/IDS/ folder.

# More Features

If you want the script to notify you realtime for potential intrusions you can make a quick 10 line script with python and add it as a Broadcast.py
In logreader.py uncomment every line that is tagged as #-- removed --
I didn't include any scripts about broadcast. If you want to proceed with it i'd advice to open a port with authentication and make an app to notify you on your phone to connect to it and check it.. Another way to do this, is by adding an smtp server and sending mails. (Faster) 
If you don't want to make an smtp server you can consider using smpt.gmail.com service

