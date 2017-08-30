#-*- coding : cp949 -*-
#-*- coding : utf-8 -*-

import sys
import os

if len(sys.argv) is 1:
	print "Usage [./filename] [Path]" 

Path = sys.argv[1]

""" Path -> Set the path manually search"""

#if switch is 1 :
#	print "Window Web Log Analysis!!"
#	Path = "C:\\inetpub\\logs\\LogFiles" """-> When you want to analyze Window Web Log(IIS) """
#if switch is 2 :
#	print "Linux Web Log Analysis!!"
#	Path = "/var/log/apache2/access.log" """-> When you want to analyze Linux Web Log(NCSA)"""

# Use for Window
f = open("./log_file_name.txt", 'w') # If the log file exists, create a file to save it

def search(dirname):
	filenames = os.listdir(dirname)
	for filename in filenames :
		full_filename = os.path.join(dirname, filename)
		if os.path.isdir(full_filename) : # If the subdirectory exists, examine the files under that directory
			search(full_filename)
		else :
			ext = os.path.splitext(full_filename)[-1] 
			if ext ==".log": # Extract only files that have an extension of '.log' to an absolute path
				f.write(os.path.dirname(os.path.abspath(__file__)) + full_filename + "\n")
search(Path)
f.close()

s = open("./log_file_name.txt", 'r') # Open the file where the log files are stored to read the log file name
z = open("./POST_log.txt", 'w') # Generate a file to save only logs using the POST method among the log files
log_file = s.readlines() 
for i in xrange(0, len(log_file)) :
	log_file_name = log_file[i][0:log_file[i].find('\n')]
	t = open(log_file_name, 'r')
	z.write (log_file_name + "\n") # In POST_log.tx, set the file name to distinguish which log file the log was extracted from
	while True: # Read the contents line by line and end the while loop if there are no more lines to read
		log_content = t.readline()
		if not log_content: break
		if (log_content.find(' POST ')!=-1): # Only the 'POST' method is filtered out from the log record
			post_log_content = log_content.split(' ')[0] + " " + log_content.split(' ')[1] + " " + log_content.split(' ')[4] + " " + log_content.split(' ')[5]+ " " + log_content.split(' ')[9] + " " + log_content.split(' ')[11] + " " + log_content.split(' ')[13]
			# Extract only the desired part of the post method record (Date, Time, Method, URI Steam & Query, Attacker IP, Status_Code, Size)
			z.write(post_log_content)
	z.write("\n")

z.close()		
t.close()
s.close()