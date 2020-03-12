import untangle
import sys
import argparse
import os

usage = """
$ python ./%(prog)s -x <path to .xml file> -o <output file>

Example: ./%(prog)s -x ./nmap.xml -o output.tsv

"""
parser = argparse.ArgumentParser(usage=usage)
parser.add_argument('-x', help='Path to .xml file.', dest='xml', action='store')
parser.add_argument('-o', help='Output file name. Otherwise STDOUT', dest='outName', action='store')
parser.add_argument('--outputScope', help='Output file name.', dest='outScope', action='store')
parser.add_argument('-v', help='Verbose.', dest='verbose', action='store_true', default=False)
parser.add_argument('--ms17_010', help='Only parse for ms17-010.', dest='ms17', action='store_true', default=False)
parser.add_argument('--ms08_067', help='Only parse for ms08-067.', dest='ms08', action='store_true', default=False)
if len(sys.argv)==1:
	parser.print_help()
	sys.exit(1)
opts = parser.parse_args()

try:
	nmap = untangle.parse(opts.xml)
except ValueError:
	print()
	print("[!] Path to .xml option required (-x <path to .xml file>)")
	sys.exit()

overwrite = False
line = ""
ms08 = False
ms17 = False

if not opts.ms08 and not opts.ms17:
	ms08 = True
	ms17 = True
if opts.ms08:
	ms08  = True
if opts.ms17:
	ms17 = True

if opts.outScope:
	if os.path.isfile(opts.outScope):
		os.remove(opts.outScope)

if opts.outName:
	opts.outName = os.path.splitext(opts.outName)[0]+'.tsv'
	if os.path.isfile(opts.outName):
		for retry in range(3):
			answer =  input("\n[?] Do you want to overwrite " + opts.outName + "? [Y/n]: ") or "y"
			if answer.lower() in ("no", "n"):
				print("[*] Appending to existing file...")
				break
			elif answer.lower() not in ("yes", "y"):
				print("[!] %s is not a valid choice." %answer)
			else:
				print("[*] Replacing existing file...")
				os.remove(opts.outName)
				overwrite = True
				break
		else:
			print("\n[!] You have provided to many invalid choices. Goodbye.")
			sys.exit()
		

def output(line):
	global overwrite
	if opts.outName:
		if overwrite:
			with open(opts.outName, "w") as f:
				f.write(line + "\n")
			f.close()
			overwrite = False
		else:
			with open(opts.outName, "a") as f:
				f.write(line + "\n")
			f.close()

def outputScope(line):
	if opts.outScope:
		with open(opts.outScope, "a") as f:
			f.write(line + "\n")
		f.close()

for i in nmap.nmaprun.host:
	try:
		for script in i.hostscript.script:
			if script["id"] == "smb-vuln-ms08-067":
				if ms08:
					for table in script.table:
						if table["key"] == "CVE-2008-4250":
							for elem in table.elem:
								if elem["key"] == "state":
									try:
										for hostname in i.hostnames.hostname:
											line = (i.address["addr"] + "\t" + elem.cdata + "\tms08-067\t" + hostname["name"])
											outputScope(hostname["name"])
									except AttributeError:
										line = (i.address["addr"] + "\t" + elem.cdata + "\tms08-067")
									outputScope(i.address["addr"])
			if script["id"] == "smb-vuln-ms17-010":
				if ms17:
					try:
						for table in script.table:
							if table["key"] == "CVE-2017-0143":
								for elem in table.elem:
									if elem["key"] == "state":
										try:
											for hostname in i.hostnames.hostname:
												line = (i.address["addr"] + "\t" + elem.cdata + "\tms17-010\t" + hostname["name"])
												outputScope(hostname["name"])
										except AttributeError:
											line = (i.address["addr"] + "\t" + elem.cdata + "\tms17-010")
										outputScope(i.address["addr"])
					except AttributeError:
						try:
							for hostname in i.hostnames.hostname:
								line = (i.address["addr"] + "\t" + script["output"] + "\tms17-010\t" + hostname["name"])
								outputScope(hostname["name"])
						except AttributeError:
							line = (i.address["addr"] + "\t" + script["output"] + "\tms17-010")
						outputScope(i.address["addr"])
	except AttributeError:
		try:
			line = (i.address["addr"] + "\tNOT VULNERABLE" + "\t" + i.hostnames.hostname["name"])
		except AttributeError:
			line = (i.address["addr"] + "\tNOT VULNERABLE")
		
	if line:
		if opts.verbose or not opts.outName:
			print(line)
		output(line)
