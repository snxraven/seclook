#!/usr/bin/python
import json
import re

# Set up Storage
trans = []
audit_data = []

with open('/var/log/httpd/modsec_audit.log') as f:
     for jsonObj in f:	         
         # Parse The JSON Data for the two types of data input
         # Lets send the data to the transaction array
         transDict = json.loads(jsonObj)
         trans.append(transDict)
         
         # Fixng JSON Formatting and Syntax
         trans_audit_data = json.dumps(transDict["audit_data"]).replace("tre", "\"tre\"")
         # The log is still hard to read, lets fix this with some regex 
         # Line 21: Adds a line Break Before any [ 
         # Line 22 Removes Non Needed Slashes 
         dataParsePretty = re.sub(r'\[', '\n[', trans_audit_data)
         dataParseNoSlash = re.sub(r'\\', '', dataParsePretty)
         # Sending the Audit Log to the audit_data storage
         audit_data.append(dataParseNoSlash)

# We have Data, now we need to loop through it
for event in trans:
  for log in audit_data:
   # More attempts to make things a bit more pretty
   transactionDump = json.dumps(event["transaction"])
   transactionDumpParsed = json.loads(transactionDump)
   # Print Our DATA!
   print ("\n")
   print ("--")
   print ("Transaction ID: "  + str(transactionDumpParsed["transaction_id"]))   
   print ("Time: "  + str(transactionDumpParsed["time"]))
   print ("Local Address: "  + str(transactionDumpParsed["local_address"]))   
   print ("Local Port: "  + str(transactionDumpParsed["local_port"]))
   print ("Remote Address: "  + str(transactionDumpParsed["remote_address"]))
   print ("Remote Port: "  + str(transactionDumpParsed["remote_port"]))
   print ("--\n")
  
   print ("--")
   print (log)   
   print ("--")


