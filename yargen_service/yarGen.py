#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen
# A rule generator for Yara rules
#
# Florian Roth

import os
import sys
import argparse
import re
import traceback
import pickle
import gzip
import operator
import datetime
import time
from hashlib import sha1
from collections import OrderedDict

from lib import gibDetector

RELEVANT_EXTENSIONS = [ ".asp", ".vbs", ".ps", ".ps1", ".rar", ".tmp", ".bas", ".bat", ".chm", ".cmd", ".com", ".cpl",
						 ".crt", ".dll", ".exe", ".hta", ".js", ".lnk", ".msc", ".ocx", ".pcd", ".pif", ".pot", ".reg",
						 ".scr", ".sct", ".sys", ".vb", ".vbe", ".vbs", ".wsc", ".wsf", ".wsh", ".ct", ".t", ".input",
						 ".war", ".jsp", ".php", ".asp", ".aspx", ".psd1", ".psm1" ]

def getFiles(dir, notRecursive):
	# Recursive
	if notRecursive:
		for filename in os.listdir(dir):
			filePath = os.path.join(dir,filename)
			yield filePath
	# Non recursive
	else:

		for root, directories, files in os.walk (dir, followlinks=False):
			for filename in files:
				filePath = os.path.join(root,filename)
				yield filePath

def parseSample(yargen_array, generateInfo=False, onlyRelevantExtensions=False, critsMessage=""):
	
	# Prepare dictionary
	string_stats = {}
	file_info = {}
	known_sha1s = []
	for critsSample in yargen_array:
		#Get Extension
		extension = os.path.splitext(yargen_array[critsSample]['filename'])[1].lower()
		#critsMessage+="Extension for %s is %s\r\n" % (yargen_array[critsSample]['filename'], extension)
		if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
			#print "EXTENSION %s - Skipping file %s" % ( extension, yargen_array[critsSample]['filename'] )
			critsMessage+="EXTENSION %s - Skipping file %s\r\n" % ( extension, yargen_array[critsSample]['filename'] )
			continue
			
		#Size Check
		#critsMessage+="%s is %s in size\r\n" % (yargen_array[critsSample]['filename'], yargen_array[critsSample]['size'])
		try:
			if yargen_array[critsSample]['size'] > 3000000:
				continue
		except Exception, e:
			pass
			
		#Extract strings from file
		critsMessage+="Extracting strings from %s\r\n" % (yargen_array[critsSample]['filename'])
		( strings, sha1sum ) = extractStrings(yargen_array[critsSample]['filedata'], generateInfo)
		
		#DEBUG
		#critsMessage+="Strings found in %s\r\n" % (yargen_array[critsSample]['filename'])
		#for string in strings:
		#	critsMessage+="%s" % (string)
		
		# Skip if SHA1 already known - avoid duplicate files
		if sha1sum in known_sha1s:
			print "Skipping strings from %s due to sha1 duplicate detection" % yargen_array[critsSample]['filename']
			critsMessage+="Skipping strings from %s due to sha1 duplicate detection\r\n" % yargen_array[critsSample]['filename']
			continue
		
		# Add SHA1 value
		if generateInfo:
			known_sha1s.append(sha1sum)
			file_info[yargen_array[critsSample]['filename']] = {}
			file_info[yargen_array[critsSample]['filename']]["sha1"] = sha1sum
			
		# Add strings to statistics
		invalid_count = 0
		for string in strings:
			if string in string_stats:
				string_stats[string]["count"] += 1
				string_stats[string]["files"].append(yargen_array[critsSample]['filename'])
			else:
				string_stats[string] = {}
				string_stats[string]["count"] = 0
				string_stats[string]["files"] = []
				string_stats[string]["files"].append(yargen_array[critsSample]['filename'])

		
		#print "Processed " + filePath + " Size: "+ str(size) +" Strings: "+ str(len(string_stats)) + " ... "				
		critsMessage+="Processed " + yargen_array[critsSample]['filename'] + " Size: "+ str(yargen_array[critsSample]['size']) +" Strings: "+ str(len(string_stats)) + " ... \r\n"
					
	return string_stats, file_info, critsMessage
	
'''
def parseMalDir(dir, notRecursive=False, generateInfo=False, onlyRelevantExtensions=False):

	# Prepare dictionary
	string_stats = {}
	file_info = {}
	known_sha1s = []
	
	for filePath in getFiles(dir, notRecursive):
		# Get Extension
		extension = os.path.splitext(filePath)[1].lower()
		if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
			if args.debug:
				print "EXTENSION %s - Skipping file %s" % ( extension, filePath )
			continue
		
		# Size Check
		size = 0
		try:
			size = os.stat(filePath).st_size
			if size > 3000000:
				continue
		except Exception, e:
			pass
			
		# Extract strings from file
		( strings, sha1sum ) = extractStrings(filePath, generateInfo)
		
		# Skip if sha1 already known - avoid duplicate files
		if sha1sum in known_sha1s:
			#if args.debug:
			print "Skipping strings from %s due to sha1 duplicate detection" % filePath
			continue
		
		# Add sha1 value
		if generateInfo:
			known_sha1s.append(sha1sum)
			file_info[filePath] = {}
			file_info[filePath]["sha1"] = sha1sum
		
		# Add strings to statistics
		invalid_count = 0
		for string in strings:
			if string in string_stats:
				string_stats[string]["count"] += 1
				string_stats[string]["files"].append(filePath)
			else:
				string_stats[string] = {}
				string_stats[string]["count"] = 0
				string_stats[string]["files"] = []
				string_stats[string]["files"].append(filePath)

		if args.debug:
			print "Processed " + filePath + " Size: "+ str(size) +" Strings: "+ str(len(string_stats)) + " ... "				
					
	return string_stats, file_info			


def parseGoodDir(dir, notRecursive=False, onlyRelevantExtensions=True):

	# Prepare dictionary
	all_strings = []

	for filePath in getFiles(dir, notRecursive):
		# Get Extension
		extension = os.path.splitext(filePath)[1].lower()
		if not extension in RELEVANT_EXTENSIONS and onlyRelevantExtensions:
			if args.debug:
				print "EXTENSION %s - Skipping file %s" % ( extension, filePath )
			continue

		# Size Check
		size = 0
		try:
			size = os.stat(filePath).st_size
			if size > 3000000:
				continue
		except Exception, e:
			pass

		# Extract strings from file
		( strings, sha1sum ) = extractStrings(filePath, generateInfo=False)
		# Append to all strings
		all_strings += strings

	# return it as a set (unique strings)
	return set(all_strings)
'''

def extractStrings(data, generateInfo):
	#String list
	strings = []
	cleaned_strings = []
	sha1sum = ""
	try:
		#Generate the sha1
		if generateInfo:
			sha1sum = sha1(data).hexdigest()
			
		#Read Strings
		strings = re.findall("[\x1f-\x7e]{6,}", data)
		strings += [str("UTF16LE:%s" % ws.decode("utf-16le")) for ws in re.findall("(?:[\x1f-\x7e][\x00]){6,}", data)]
		
		# Escape strings
		for string in strings:
			# Check if last bytes have been string and not yet saved to list
			if len(string) > 0:
				string = string.replace('\\','\\\\')
				string = string.replace('"','\\"')
				if not string in cleaned_strings:
					cleaned_strings.append(string.lstrip(" "))
				
	except Exception,e:
		if args.debug:
			traceback.print_exc()
		pass
		
	return cleaned_strings, sha1sum
			
'''
def extractStrings(filePath, generateInfo):
	# String list
	strings = []
	cleaned_strings	= []
	sha1sum = ""
	# Read file data
	try:
		f = open(filePath, 'rb')
		data = f.read()
		f.close()
		# Generate sha1
		if generateInfo:
			sha1sum = sha1(data).hexdigest()
		
		# Read strings
		strings = re.findall("[\x1f-\x7e]{6,}", data)
		strings += [str("UTF16LE:%s" % ws.decode("utf-16le")) for ws in re.findall("(?:[\x1f-\x7e][\x00]){6,}", data)]
		
		# Escape strings
		for string in strings:
			# Check if last bytes have been string and not yet saved to list
			if len(string) > 0:
				string = string.replace('\\','\\\\')
				string = string.replace('"','\\"')
				if not string in cleaned_strings:
					cleaned_strings.append(string.lstrip(" "))
				
	except Exception,e:
		if args.debug:
			traceback.print_exc()
		pass
		
	return cleaned_strings, sha1sum

'''
def filterStringSet(string_set):
	
	# This is the only set we have - even if it's a weak one
	useful_set = []
	
	# Gibberish Detector
	gib = gibDetector.GibDetector()
	
	# String scores
	stringScores = {}
	utfstrings = []
	for string in string_set:

		# UTF
		if string[:8] == "UTF16LE:":
			string = string[8:]
			utfstrings.append(string)
			
		# Gibberish Score
		score = gib.getScore(string)
		# score = 1
		if score > 10:
			score = 1
		#if args.debug:
			#print "%s - %s" % ( str(score), string)
		stringScores[string] = score
		
		# Length Score
		length = len(string)
		#if length > int(args.l) and length < int(args.s):
		if length > int(6) and length < int(64):
			stringScores[string] += round( len(string) / 8, 2)
		#if length >= int(args.s):
		if length >= int(64):
			stringScores[string] += 1

		# In suspicious strings
		#if string in suspicious_strings:
		#	stringScores[string] += 6

		# Reduction
		if ".." in string:
			stringScores[string] -= 5
		if "   " in string:
			stringScores[string] -= 5

		# Certain strings add-ons ----------------------------------------------
		# Extensions - Drive
		if re.search(r'([A-Za-z]:\\|\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.[a-z][a-z][a-z])', string, re.IGNORECASE):
			stringScores[string] += 4
		# System keywords
		if re.search(r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log|unc)', string, re.IGNORECASE):
			stringScores[string] += 5
		# Protocol Keywords
		if re.search(r'(ftp|irc|smtp|command|GET|POST|Agent|tor2web|HEAD)', string, re.IGNORECASE):
			stringScores[string] += 5
		# Connection keywords
		if re.search(r'(error|http|closed|failed|failure|version)', string, re.IGNORECASE):
			stringScores[string] += 3
		# Browser User Agents
		if re.search(r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', string, re.IGNORECASE):
			stringScores[string] += 4
		# Temp and Recycler
		if re.search(r'(TEMP|Temporary|Appdata|Recycler)', string, re.IGNORECASE):
			stringScores[string] += 4
		# malicious keywords - hacktools
		if re.search(r'(scan|sniff|poison|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|credentials|creds|coded|p0c|Content|host)', string, re.IGNORECASE):
			stringScores[string] += 5
		# network keywords
		if re.search(r'(address|port|listen|remote|local|process|service|mutex|pipe|frame|key|lookup|connection)', string, re.IGNORECASE):
			stringScores[string] += 3
		# Drive non-C:
		if re.search(r'([D-Z]:\\)', string, re.IGNORECASE):
			stringScores[string] += 4
		# IP
		if re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', string, re.IGNORECASE): # IP Address
			stringScores[string] += 5
		# Copyright Owner
		if re.search(r'( by | coded | c0d3d |cr3w\b)', string, re.IGNORECASE):
			stringScores[string] += 2
		# Extension generic
		if re.search(r'\.[a-zA-Z]{3}\b', string):
			stringScores[string] += 3
		# All upper case
		if re.search(r'^[A-Z]{6,}$', string):
			stringScores[string] += 2
		# All lower case
		if re.search(r'^[a-z]{6,}$', string):
			stringScores[string] += 2
		# All lower with space
		if re.search(r'^[a-z\s]{6,}$', string):
			stringScores[string] += 2
		# All characters
		if re.search(r'^[A-Z][a-z]{5,}', string):
			stringScores[string] += 2
		# URL
		if re.search(r'(%[a-z][:\-,;]|\\\\%s|\\\\[A-Z0-9a-z%]+\\[A-Z0-9a-z%]+)', string):
			stringScores[string] += 3
		# certificates
		if re.search(r'(thawte|trustcenter|signing|class|crl|CA|certificate|assembly)', string, re.IGNORECASE):
			stringScores[string] -= 4
		# Parameters
		if re.search(r'( \-[a-z]{,2}[\s]?[0-9]?| /[a-z]+[\s]?[\w]*)', string, re.IGNORECASE):
			stringScores[string] += 4
		# Directory
		if re.search(r'(\\[A-Za-z]+\\)', string):
			stringScores[string] += 4
		# Executable - not in directory
		if re.search(r'^[^\\]+\.(exe|com|scr|bat)$', string, re.IGNORECASE):
			stringScores[string] += 4
		# Date placeholders
		if re.search(r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', string, re.IGNORECASE):
			stringScores[string] += 3
		# Placeholders
		if re.search(r'(%s|%d|%i)', string, re.IGNORECASE):
			stringScores[string] += 3

		# Certain string reduce	-----------------------------------------------
		if re.search(r'(rundll32\.exe$|kernel\.dll$)', string, re.IGNORECASE):
			stringScores[string] -= 4			
	
	sorted_set = sorted(stringScores.iteritems(), key=operator.itemgetter(1), reverse=True)
	
	#if args.debug:
		#print "SORTED SET:"
		#print sorted_set

	# Only the top X strings
	c = 0
	result_set = []
	for string in sorted_set:
		if string[0] in utfstrings:
			result_set.append("UTF16LE:%s" % string[0])
		else:
			result_set.append(string[0])
		c += 1
		#if c > int(args.rc):
		if c > int(20):
			break

	#if args.debug:
		#print "RESULT SET:"
		#print result_set
	
	# return the filtered set
	return result_set


def readPEStudioStrings():
	tree = etree.parse('PeStudioBlackListStrings.xml')
	string_elems = tree.findall(".//String")
	strings = []
	for elem in string_elems:
		strings.append(elem.text)
	return strings


def getTimestampBasic(date_obj=None):
	if not date_obj:
		date_obj = datetime.datetime.now()
	date_str = date_obj.strftime("%Y/%m/%d")
	return date_str


def isAscii(b):
	if ord(b)<127 and ord(b)>31 :
		return 1 
	return 0


def save(object, filename, bin = 1):
	file = gzip.GzipFile(filename, 'wb')
	file.write(pickle.dumps(object, bin))
	file.close()


def load(filename):
	file = gzip.GzipFile(filename, 'rb')
	buffer = ""
	while 1:
		data = file.read()
		if data == "":
			break
		buffer += data
	object = pickle.loads(buffer)
	del(buffer)
	file.close()
	return object


def printWelcome():
	print "###############################################################################"
	print "  "
	print "  yarGen"
	print "  Yara Rule Generator"
	print "  "
	print "  by Florian Roth"
	print "  January 2015"
	print "  Version 0.10.0"
	print " "
	print "###############################################################################"                               


# MAIN ################################################################
def runMain(yargen_array, critsMessage):
	#if __name__ == '__main__':
	
	# Parse Arguments
	parser = argparse.ArgumentParser(description='yarGen')
	parser.add_argument('-m', help='Path to scan for malware')
	parser.add_argument('-g', help='Path to scan for goodware (dont use the database shipped with yara-brg)')
	parser.add_argument('-u', action='store_true', default=False, help='Update local goodware database (use with -g)')
	parser.add_argument('-c', action='store_true', default=False, help='Create new local goodware database (use with -g)')	
	parser.add_argument('-o', help='Output rule file', metavar='output_rule_file', default='yargen_rules.yar')
	parser.add_argument('-p', help='Prefix for the rule description', metavar='prefix', default='Auto-generated rule')
	parser.add_argument('-a', help='Athor Name', metavar='author', default='YarGen Rule Generator')
	parser.add_argument('-r', help='Reference', metavar='ref', default='not set')
	parser.add_argument('-l', help='Minimum string length to consider (default=6)', metavar='min-size', default=5)
	parser.add_argument('-s', help='Maximum length to consider (default=64)', metavar='max-size', default=64)
	parser.add_argument('-nr', action='store_true', default=False, help='Do not recursively scan directories')
	# parser.add_argument('-rm', action='store_true', default=False, help='Recursive scan of malware directories')
	# parser.add_argument('-rg', action='store_true', default=False, help='Recursive scan of goodware directories')
	parser.add_argument('-oe', action='store_true', default=False, help='Only scan executable extensions EXE, DLL, ASP, JSP, PHP, BIN, INFECTED')
	parser.add_argument('-fs', help='Max file size to analyze (default=2000000)', metavar='dir', default=2000000)
	parser.add_argument('-rc', help='Maximum number of strings per rule (default=20, intelligent filtering will be applied)', metavar='maxstrings', default=20)
	parser.add_argument('--nosuper', action='store_true', default=False, help='Don\'t try to create super rules that match against various files')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

	args = parser.parse_args()
	suspicious_strings = []
	'''
	# Print Welcome
	printWelcome()

	# Read PEStudio string list
	suspicious_strings = []
	if os.path.exists("PeStudioBlackListStrings.xml") and lxml_available:
		suspicious_strings = readPEStudioStrings()
	else:
		if lxml_available:
			print "To improve the analysis process please download PEStudio from http://winitor.com and place the file 'PeStudioBlackListStrings.xml' in the yarGen program directory."
			time.sleep(5)

	# Ignore File Type on Malware Scan
	onlyRelevantExtensions = False
	if args.oe:
		onlyRelevantExtensions = True

	# Scan goodware files
	if args.g:
		print "Processing goodware files ..."
		good_strings = parseGoodDir(args.g, args.nr, True)
		
		# Update existing Pickle
		if args.u:
			print "Updating local database ..."
			try:
				good_pickle = load("good_strings.db")
				print "Old database entries: %s" % len(good_pickle)
				new_good = set()
				new_good = good_strings | good_pickle
				good_pickle = new_good
				print "New database entries: %s" % len(good_pickle)
				save(good_pickle, "good_strings.db")

			except Exception, e:
				traceback.print_exc()

		# Create new Pickle
		if args.c:
			print "Creating local database ..."
			try:
				if os.path.isfile("good_strings.db"):
					os.remove("good_strings.db")

				good_pickle = set()
				good_pickle = good_strings

				save(good_pickle, "good_strings.db")

				print "New database with %s entries created." % len(good_pickle)
			except Exception, e:
				traceback.print_exc()

	# Don't use the Database
	else:
		print "Reading goodware files from database 'good_strings.db' ..."
	'''
	#critsMessage=""
	try:
		from lxml import etree
		lxml_available = True
	except Exception, e:
		#print "lxml not found - disabling PeStudio string check functionality"
		critsMessage+="lxml not found - disabling PeStudio string check functionality\r\n"
		lxml_available = False

	critsMessage+="Reading goodware files from database 'good_strings.db' ...\r\n\r\n"
	# Load the Existing DB
	try:
		fullDBPath = os.path.dirname(os.path.abspath(__file__))
		fullDBPath += "/good_strings.db"
		good_pickle = load(fullDBPath)
		# print good_pickle.keys()
		good_strings = good_pickle
		
	except Exception, e:
		traceback.print_exc()
		critsMessage=traceback.format_exc()
		critsMessage+="\r\n\r\nDirectory Script is being run in - "
		critsMessage+=os.path.dirname(os.path.abspath(__file__))
		critsMessage+="\r\n\r\nCurrent Working Directory - "
		critsMessage+=os.getcwd()
		return critsMessage

	# If malware directory given
	#if args.m:
	# Scan malware files
	#print "Processing malware files ..."
	critsMessage+="Processing malware files ...\r\n"
	#mal_string_stats, file_info_mal = parseMalDir(args.m, args.nr, True, onlyRelevantExtensions)
	mal_string_stats, file_info_mal, critsMessage = parseSample(yargen_array, True, onlyRelevantExtensions=False, critsMessage=critsMessage)
		
	# Generate Stats --------------------------------------------------
	#print "Generating statistical data ..."
	critsMessage+="\r\nGenerating statistical data ...\r\n"
	file_strings = {}
	combinations = {}
	max_combi_count = 0

	# Iterate through strings found in malware files
	for string in mal_string_stats:
		
		# Skip if string is a good string
		if string in good_strings:
			continue
		
		# If string occurs not too often in malware files
		if mal_string_stats[string]["count"] < 10:
			#if args.debug:
				# print "String: " +string +" Found in: "+ ", ".join(mal_string_stats[string]["files"])
				#pass
			# If string list in file dictionary not yet exists
			for file in mal_string_stats[string]["files"]:
				if file in file_strings:
					# Append string
					file_strings[file].append(string)
				else:
					# Create list and than add the first string to the file
					file_strings[file] = []
					file_strings[file].append(string)
		
		# SUPER RULES GENERATOR	- preliminary work					
		# If a string occurs more than once in different files
		if mal_string_stats[string]["count"] > 1:
			#print "OVERLAP Count: %s\nString: \"%s\"%s" % ( mal_string_stats[string]["count"], string, "\nFILE: ".join(mal_string_stats[string]["files"]) )
			critsMessage+="\r\nOVERLAP Count: %s\nString: \"%s\"%s\r\n" % ( mal_string_stats[string]["count"], string, "\nFILE: ".join(mal_string_stats[string]["files"]) )
			# Create a cobination string from the file set that matches to that string
			combi = ":".join(sorted(mal_string_stats[string]["files"]))
			# print "STRING: " + string
			# print "COMBI: " + combi
			# If combination not yet known
			if not combi in combinations:
				combinations[combi] = {}
				combinations[combi]["count"] = 1
				combinations[combi]["strings"] = []
				combinations[combi]["strings"].append(string)
				combinations[combi]["files"] = mal_string_stats[string]["files"]
			else:
				combinations[combi]["count"] += 1
				combinations[combi]["strings"].append(string)
			# Set the maximum combination count
			if combinations[combi]["count"] > max_combi_count:
				max_combi_count = combinations[combi]["count"]
				# print "Max Combi Count set to: %s" % max_combi_count 

	# SUPER RULE GENERATION -------------------------------------------
	super_rules = []
	supergen = True
	#if not args.nosuper:
	if supergen:
		#print "Generating Super Rules ... (a lot of foo magic)"
		critsMessage+="\r\nGenerating Super Rules ... (a lot of foo magic)\r\n"
		for combi_count in range(max_combi_count, 1, -1):
			for combi in combinations:
				if combi_count == combinations[combi]["count"]:
					#print "Count %s - Combi %s" % ( str(combinations[combi]["count"]), combi )
					# Filter the string set
					#print "BEFORE"
					#print len(combinations[combi]["strings"])
					string_set = combinations[combi]["strings"]
					combinations[combi]["strings"] = []
					combinations[combi]["strings"] = filterStringSet(string_set)
					#print "AFTER"
					#print len(combinations[combi]["strings"])
					# Combi String count after filtering
					#print "String count after filtering: %s" % str(len(combinations[combi]["strings"]))
					# If the string set of the combination has a required size
					#if len(combinations[combi]["strings"]) >= int(args.rc):
					if len(combinations[combi]["strings"]) >= int(20):
						# Remove the files in the combi rule from the simple set
						for file in combinations[combi]["files"]:
							if file in file_strings:
								del file_strings[file]
						# Add it as a super rule
						#print "Adding Super Rule with %s strings." % str(len(combinations[combi]["strings"]))
						critsMessage+="Adding Super Rule with %s strings.\r\n" % str(len(combinations[combi]["strings"]))
						super_rules.append(combinations[combi])
						
	# PROCESS SIMPLE RULES					
	# Apply intelligent filters ---------------------------------------
	#print "Applying intelligent filters to string findings ..."
	critsMessage+="\r\nApplying intelligent filters to string findings ...\r\n"
	for filePath in file_strings:
					
		# Replace the original string set with the filtered one
		string_set = file_strings[filePath]
		file_strings[filePath] = []
		file_strings[filePath] = filterStringSet(string_set)

	# Write to file ---------------------------------------------------
	filewrite = False
	#if args.o:
	if filewrite:
		try:
			fh = open(args.o, 'w')
		except Exception, e: 
			traceback.print_exc()

	# GENERATE SIMPLE RULES -------------------------------------------
	#print "Generating simple rules ..."
	critsMessage+="Generating simple rules ...\r\n"
	rules = ""
	printed_rules = {}
	rule_count = 0
	for filePath in file_strings:
		try:
			rule = ""
			(path, file) = os.path.split(filePath)
			# Prepare name
			fileBase = os.path.splitext(file)[0]
			# Create a clean new name
			cleanedName = fileBase
			# Adapt length of rule name
			if len(fileBase) < 8: # if name is too short add part from path
				cleanedName = path.split('\\')[-1:][0] + "_" + cleanedName
			# File name starts with a number
			if re.search(r'^[0-9]', cleanedName):
				cleanedName = "sig_" + cleanedName
			# clean name from all characters that would cause errors
			cleanedName = re.sub('[^\w]', r'_', cleanedName)
			# Check if already printed
			if cleanedName in printed_rules:
				printed_rules[cleanedName] += 1
				cleanedName = cleanedName + "_" + str(printed_rules[cleanedName])
			else:
				printed_rules[cleanedName] = 1
			# Print rule title
			rule += "rule %s {\n" % cleanedName
			rule += "\tmeta:\n"
			rule += "\t\tdescription = \"%s - file %s\"\n" % ( 'Auto-generated rule', file )
			#rule += "\t\tdescription = \"%s - file %s\"\n" % ( args.p, file )
			#rule += "\t\tauthor = \"%s\"\n" % args.a
			rule += "\t\tauthor = \"CRITs YarGen Service\"\n"
			#rule += "\t\treference = \"%s\"\n" % args.r
			rule += "\t\treference = \"not set\"\n"
			rule += "\t\tdate = \"%s\"\n" % getTimestampBasic()
			rule += "\t\thash = \"%s\"\n" % file_info_mal[filePath]["sha1"]
			rule += "\tstrings:\n"
			# Adding the strings
			for i, string in enumerate(file_strings[filePath]):
				# Checking string length
				fullword = True
				if len(string) > 80:
					# cut string
					string = string[:80].rstrip("\\")
					# not fullword anymore
					fullword = False
				# Add rule
				enc = " ascii"
				if string[:8] == "UTF16LE:":
					string = string[8:]
					enc = " wide"
				if fullword:
					rule += "\t\t$s%s = \"%s\" fullword%s\n" % ( str(i), string, enc )
				else:
					rule += "\t\t$s%s = \"%s\"%s\n" % ( str(i), string, enc )
				# If too many string definitions found - cut it at the 
				# count defined via command line param -rc
				#if i > int(args.rc):
				if i > int(20):
					break
			rule += "\tcondition:\n"
			rule += "\t\tall of them\n"		
			rule += "}\n"
			# print rule
			# Add to rules string 
			rules += rule
			# Try to write rule to file
			writefile=False
			#if args.o:
			if writefile:
				fh.write(rule)	
			rule_count += 1
		except Exception, e:
			traceback.print_exc()	
			
	# GENERATE SUPER RULES --------------------------------------------
	supergen = True
	#if not args.nosuper:
	if supergen:
		#print "Generating super rules ..."
		critsMessage+="Generating super rules ...\r\n"
		printed_combi = {}
		super_rule_count = 0
		for super_rule in super_rules:
			try:
				rule = ""
				# Prepare Name
				rule_name = ""
				file_list = []
				# Loop through files
				for filePath in super_rule["files"]:
					(path, file) = os.path.split(filePath)
					file_list.append(file)
					# Prepare name
					fileBase = os.path.splitext(file)[0]
					# Create a clean new name
					cleanedName = fileBase
					# Append it to the full name
					rule_name += "_" + cleanedName
					
				# Create a list of files
				file_listing = ", ".join(file_list)
						
				# File name starts with a number
				if re.search(r'^[0-9]', rule_name):
					rule_name = "sig_" + rule_name
				# clean name from all characters that would cause errors
				rule_name = re.sub('[^\w]', r'_', rule_name)
				# Check if already printed
				if rule_name in printed_rules:
					printed_combi[rule_name] += 1
					rule_name = rule_name + "_" + str(printed_combi[rule_name])
				else:
					printed_combi[rule_name] = 1
						
				# Print rule title
				rule += "rule %s {\n" % rule_name
				rule += "\tmeta:\n"
				#rule += "\t\tdescription = \"%s - from files %s\"\n" % ( args.p, file_listing )
				rule += "\t\tdescription = \"%s - from files %s\"\n" % ( 'Auto-Generated Rule', file_listing )
				#rule += "\t\tauthor = \"%s\"\n" % args.a
				rule += "\t\tauthor = \"CRITs YarGen Service\"\n"
				#rule += "\t\treference = \"%s\"\n" % args.r
				rule += "\t\treference = \"not set\"\n"
				rule += "\t\tdate = \"%s\"\n" % getTimestampBasic()					
				rule += "\t\tsuper_rule = 1\n"
				for i, filePath in enumerate(super_rule["files"]):
					rule += "\t\thash%s = \"%s\"\n" % (str(i), file_info_mal[filePath]["sha1"])
				rule += "\tstrings:\n"
				# Adding the strings
				for i, string in enumerate(super_rule["strings"]):
					# Checking string length
					fullword = True
					if len(string) > 80:
						# cut string
						string = string[:80].rstrip("\\")
						# not fullword anymore
						fullword = False
					# Add rule
					wide = ""
					if string[:8] == "UTF16LE:":
						string = string[8:]
						wide = " wide"
					if fullword:
						rule += "\t\t$s%s = \"%s\" fullword%s\n" % ( str(i), string, wide )
					else:
						rule += "\t\t$s%s = \"%s\"%s\n" % ( str(i), string, wide )
					# If too many string definitions found - cut it at the 
					# count defined via command line param -rc
					#if i > int(args.rc):
					if i > int(20):
						break
				rule += "\tcondition:\n"
				rule += "\t\tall of them\n"		
				rule += "}\n"
				# print rule
				# Add to rules string 
				rules += rule
				# Try to write rule to file
				writefile = False
				if writefile:
					fh.write(rule)	
				super_rule_count += 1
			except Exception, e:
				traceback.print_exc()				

	# Close the rules file --------------------------------------------
	writefile = False
	#if args.o:
	if writefile:
		try:
			fh.close()
		except Exception, e:
			traceback.print_exc()
			
	# Print rules to command line -------------------------------------
	#if args.debug:
		#print rules
	critsMessage+="\r\n------------------------------"
	critsMessage+="\r\n Rules"
	critsMessage+="\r\n------------------------------\r\n"
	critsMessage+=rules
	critsMessage+="\r\n------------------------------\r\n"
		
	#print "Generated %s SIMPLE rules." % str(rule_count)
	critsMessage+="\r\n"
	critsMessage+="Generated %s SIMPLE rules.\r\n" % str(rule_count)
	#if not args.nosuper: 
		#print "Generated %s SUPER rules." % str(super_rule_count)
	critsMessage+="\r\n"
	critsMessage+="Generated %s SUPER rules.\r\n" % str(super_rule_count)
	#print "All rules written to %s" % args.o
	return critsMessage
		
