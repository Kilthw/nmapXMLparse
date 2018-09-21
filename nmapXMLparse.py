import untangle
import sys
import argparse

usage = """
$ python ./%(prog)s -d <path to .xml file> -o <output file>

Example: ./%(prog)s -d ./nmap.xml -o output.tsv

"""
parser = argparse.ArgumentParser(usage=usage)
parser.add_argument('-d', help='Path to .xml file.', dest='xml', action='store')
parser.add_argument('-o', help='Output name. Default: \'output.tsv\'', dest='outName', action='store', default="output.tsv")
parser.add_argument('--ms17_010', help='Only parse for ms17-010.', dest='ms17', action='store_true', default=False)
parser.add_argument('--ms08_067', help='Only parse for ms08-06.', dest='ms08', action='store_true', default=False)
if len(sys.argv)==1:
	parser.print_help()
	sys.exit(1)
opts = parser.parse_args()

try:
	nmap = untangle.parse(opts.xml)
except ValueError:
	print("[!] Path to .xml option required (-d <path to .xml file>)")
	sys.exit()

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
										print(i.address["addr"] + "  " + elem.cdata + "  ms08-067  " + hostname["name"])
								except AttributeError:
									print(i.address["addr"] + "  " + elem.cdata + "  ms08-067")
			if script["id"] == "smb-vuln-ms17-010":
				try:
					for table in script.table:
						if table["key"] == "CVE-2017-0143":
							for elem in table.elem:
								if elem["key"] == "state":
									try:
										for hostname in i.hostnames.hostname:
											print(i.address["addr"] + "  " + elem.cdata + "  ms17-010  " + hostname["name"])
									except AttributeError:
										print(i.address["addr"] + "  " + elem.cdata + "  ms17-010")
				except AttributeError:
					try:
						for hostname in i.hostnames.hostname:
							print(i.address["addr"] + "  " + script["output"] + "  ms17-010  " + hostname["name"])
					except AttributeError:
						print(i.address["addr"] + "  " + script["output"] + "  ms17-010")
		except AttributeError:
			try:
				print(i.address["addr"] + "  NOT VULNERABLE" + "  " + i.hostnames.hostname["name"])
			except AttributeError:
				print(i.address["addr"] + "  NOT VULNERABLE")
				