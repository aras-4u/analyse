#!/bin/sh
# Please perform this download only once per day
# wget http://downloads.majestic.com/majestic_million.csv

rm -rf output/bad
rm -rf output/results

mkdir output
mkdir output/temp
mkdir output/results
mkdir output/raw
mkdir output/bad

# First filter: only look at Belgian domain names and extract the raw domain name
# We will also include a whitelist of additional domains in the customhosts.txt file
# grep -f tld.txt majestic_million.csv | awk -F ',' '{print $3}' > output/temp/rawlist_temp.txt
grep "\.be$" top-1m.csv | awk -F ',' '{print $2}' > output/temp/rawlist_temp.txt
cat output/temp/rawlist_temp.txt customhosts.txt > rawlist.txt

# Download all index pages from the extracted domain list
parallel -j 60 "wget -t 3 -T 10 -O output/raw/{} {}" <rawlist.txt

# Query 1: Look for RIG Exploit Kit (rule updated 4 April 2017)
# Reference http://www.malware-traffic-analysis.net/2017/03/28/index.html
echo "Running query 1 - RIG Exploit Kit hits..."
egrep -r '<script type="text/javascript"> var.*frameBorder' output/raw/  >> output/temp/results.txt

# Query 2: Look for RIG Exploit Kit (rule updated 4 April 2017)
# Modus operandi is to use an absolute position, but position it outside of the screen (use negative values)
#
# Reference http://www.malware-traffic-analysis.net/2017/03/09/index.html
# Reference http://www.malware-traffic-analysis.net/2017/03/20/index2.html
#
echo "Running query 2 - RIG Exploit Kit hits (alt)"
egrep -A 5 -r -e 'position: absolute;.*-' output/raw/ | grep -v -e "{." -e "img src" >> output/temp/results.txt

# Query 3: Look for iframes that load an absolute page and have a height / width of 0
echo "Running query 3 - Looking for iframes loading an absolute URL and height / width 0" 
egrep -r -i -e 'iframe.*width.*"0px' -e 'iframe.height.*"0px' output/raw/ >> output/temp/results.txt
grep -A 5 -r -i "<iframe style='hidden' " output/raw/ >> output/temp/results.txt
grep -A 5 -r -i "<iframe style=\"hidden\" " output/raw/ >> output/temp/results.txt

# Query 4: Look for Angler EK (outdated)
echo "Running Query 4 - Looking for older Angler EK"
grep -r -i "hidden\" name=\"ip\" value=\"" output/raw/ >> output/temp/results.txt
grep -r -i "<script>var date = new Date(new Date().getTime() + 60*60*24*7*1000);" output/raw/ >> output/temp/results.txt
grep -r -i "width=\"1px"\" output/raw/ >> output/temp/results.txt

echo "Processing results"
egrep -v -f whitelist_domains.txt output/temp/results.txt | egrep -v -f whitelist_ext.txt > output/results/all_final.txt
grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" output/results/all_final.txt | grep -v -f rawlist.txt | sort -u  > output/temp/badurls.txt

echo "          "
echo "Raw output"
echo "----------"
cat output/results/all_final.txt

echo "                                   "
echo "Unique list of bad urls identified:"
echo "-----------------------------------"
cat output/temp/badurls.txt

# echo "Downloading bad urls to output/bad/..."
# wget -x -P output/bad -i  output/temp/badurls.txt

#echo "Processing report (this may take a while)"
#echo "-----------------------------------------"
#grep -r -o -f output/temp/badurls.txt output/raw/ > output/results/report.txt

# Get rid of temp files
rm output/temp/*

# echo "        "
# echo "Report"
# echo "------"
# cat output/results/report.txt
