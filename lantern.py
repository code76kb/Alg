import os

eye = open("/home/satyaprakash/Algo/eye.xml","r")
for line in eye:
	if(line.find("address addr") != -1):
		lines=line[14:].split(" ")
		ips = lines[0]
		ip=ips[1:len(ips)-1]
		print ip
		os.system('sudo nmap -O '+ip+'>> /home/satyaprakash/Algo/tarain.txt')
