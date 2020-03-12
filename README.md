# nmapXMLparse
nmap -Pn --open -p 445 -T4 -vvv -n -iL .\MS_Targets.txt --script smb-vuln-ms08-067,smb-vuln-ms17-010 -oX MS08067_MS17010.xml

Example: py -3 ./nmapXMLparse.py -x ./MS08067_MS17010.xml -o output.tsv

-x            Path to .xml file.
-o            Output file name. Otherwise STDOUT
-v            Verbose
--ms17_010    Only parse for ms17-010.
--ms08_067    Only parse for ms08-067.
