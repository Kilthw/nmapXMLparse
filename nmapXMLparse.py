import untangle
import sys
import argparse
import os

usage = """
$ python ./%(prog)s -d <path to .xml file> -o <output file>

Example: ./%(prog)s -d ./nmap.xml -o output.tsv

"""
parser = argparse.ArgumentParser(usage=usage)
parser.add_argument('-x', help='Path to .xml file.', dest='xml', action='store')
parser.add_argument('-o', help='Output file name. Otherwise STDOUT', dest='outName', action='store')
parser.add_argument('-v', help='Verbose.', dest='verbose', action='store_true', default=False)
parser.add_argument('--ms17_010', help='Only parse for ms17-010.', dest='ms17', action='store_true', default=False)
parser.add_argument('--ms08_067', help='Only parse for ms08-06.', dest='ms08', action='store_true', default=False)
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

if opts.outName:
	if os.path.isfile(opts.outName):
		for retry in range(5):
			answer =  input("\n[?] Do you want to overwrite " + opts.outName + "? [Y/n]: ") or "y"
			if answer.lower() in ("no", "n"):
				print("[*] Appending to existing file...")
				break
			elif answer.lower() not in ("yes", "y"):
				print("[!] %s is not a valid choice." %answer)
			else:
				print("[*] Replacing existing file...")
				overwrite = True
				break
		
	else:
		os.remove(opts.outName)

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

for i in nmap.nmaprun.host:
	for script in i.hostscript.script:
		try:
			if script["id"] == "smb-vuln-ms08-067":
				for table in script.table:
					if table["key"] == "CVE-2008-4250":
						for elem in table.elem:
							if elem["key"] == "state":
								try:
									for hostname in i.hostnames.hostname:
										line = (i.address["addr"] + "\t" + elem.cdata + "\tms08-067\t" + hostname["name"])
								except AttributeError:
									line = (i.address["addr"] + "\t" + elem.cdata + "\tms08-067")
			if script["id"] == "smb-vuln-ms17-010":
				try:
					for table in script.table:
						if table["key"] == "CVE-2017-0143":
							for elem in table.elem:
								if elem["key"] == "state":
									try:
										for hostname in i.hostnames.hostname:
											line = (i.address["addr"] + "\t" + elem.cdata + "\tms17-010\t" + hostname["name"])
									except AttributeError:
										line = (i.address["addr"] + "\t" + elem.cdata + "\tms17-010")
				except AttributeError:
					try:
						for hostname in i.hostnames.hostname:
							line = (i.address["addr"] + "\t" + script["output"] + "\tms17-010\t" + hostname["name"])
					except AttributeError:
						line = (i.address["addr"] + "\t" + script["output"] + "\tms17-010")
		except AttributeError:
			try:
				line = (i.address["addr"] + "\tNOT VULNERABLE" + "\t" + i.hostnames.hostname["name"])
			except AttributeError:
				line = (i.address["addr"] + "\tNOT VULNERABLE")
		
		if opts.verbose or not opts.outName:
			print(line)
		output(line)