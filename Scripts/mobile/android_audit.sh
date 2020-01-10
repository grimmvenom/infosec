#!/bin/bash

: <<'ENDBlock'
# Summary:
# ------------------------------
# Example: bash android_audit.sh ./demo.apk
#
# Create a project directory based on APK
# Extract information from .apk and .ipa applications and generate output
# This information can be used to assist us in manual audit tasks such as:
# finding domains, sub domains, urls, usernames, passwords, email addresses,
# api keys, etc..
#
# Authors:
#     Jeff Kitson
#     Nick Serra
#
ENDBlock

###############
# Global Variables
###############
Arg1=${1}
# Get Current Date and Time
DATE=$(date +"%Y-%m-%d")
TIME=$(date +"%I_%M_%p")
# Get directory path from filepath
DirPath=$(realpath "$(dirname ${1})")
# Get Filename from path
FILE="$(basename ${1})"
# Get AppName (Filename w/o extension)
AppName="${FILE%.*}"
# Get the extension
extension="${FILE##*.}"
FileName="${FILE%.%}"

echo "Arg1: ${1}"
echo "DirPath: ${DirPath}"
echo "FileName: $FileName"
echo "AppName: ${AppName}"
echo "Extension: ${extension}"
echo " "

###############
# User Variables (May need Tweaking)
###############
# Define Directory where apks are stored
GODIR=$(realpath "$HOME/go/fandango/apks/")
# Define Output Location
TARGETDIR="$HOME/Downloads/Reports/$AppName-$DATE_$TIME"


function project_setup {
  echo -e "\nCreating Project Directories @ $TARGETDIR"
  # Create Directories if they don't exist
  mkdir -p $TARGETDIR/{"logs","evidence","jadx","unzip"}

  # Copy Application to Target Directory
  # cp "$GODIR/$FILE" $TARGETDIR"/"$FILE
  echo "Copying: ${Arg1}"
  cp "$Arg1" "$TARGETDIR/${FileName}"
}


function decompiled_audit {
  echo -e "\nRunning Decompiled Audit"
  echo -e "================================================\n"
  # Run JADX (decompile application) on Copied version of Application
  jadx -d "$TARGETDIR/jadx" "$TARGETDIR/$FILE" > "$TARGETDIR/logs/jadx_decompile_log.txt"
  cd "$TARGETDIR/jadx"
  # Extract Files as a checklist
  echo "(DA) -> Extracting Files As Checklist"
  find . -type f | rev | sort | rev | sed "s/^/[ ] /g" > "$TARGETDIR/logs/jadx_file_checklist.txt"
  # Extract IPs
  echo "(DA) -> Extracting IPS"
  grep -RnEI ".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*" * > "$TARGETDIR/evidence/jadx_ips.txt"
  # Extract email addresses
  echo "(DA) -> Extracting Email Addresses"
  grep -RnEI ".*@.*\.com.*" * > "$TARGETDIR/evidence/jadx_emails.txt"
  # Extract Domain Names
  echo "(DA) -> Extracting Domain Names"
  grep -RnEI ".*\.com\".*" * > "$TARGETDIR/evidence/jadx_domains.txt"
  fgrep -RniI http * | grep -Eo 'http.*' | grep "://" | sort | uniq > "$TARGETDIR/evidence/jadx_http_domains.txt"
  # Extract Double Quoted Strings
  echo "(DA) -> Extracting Double Quoted Strings"
  grep -ERoI '".*"' * | grep -Eo '".*"' | cut -c2- | rev | cut -c2- | rev | sort | uniq > "$TARGETDIR/evidence/jadx_double_quoted_strings.txt"
  # Get 3rd party packages / libraries
  echo "(DA) -> Extracting Packages + Imports"
  grep -Rn "$TARGETDIR/jadx" -e "import" -e "package" | grep -Fv -e "package=" -e "package name=" -e "LICENSE" | cut -d ":" -f 2 | sort -u > "$TARGETDIR/evidence/jadx_imports.txt"
  cd $TARGETDIR
}


function unzipped_audit {
  echo -e "\nRunning UnZipped Audit"
  echo -e "================================================\n"
  cd $TARGETDIR"/unzip"
  # Unzip application instead of decompile
  unzip "$TARGETDIR/"$FILE > "$TARGETDIR/logs/unzip_log.txt"
  # Extract Files as a checklist
  echo "(UA) -> Extracting Files As Checklist"
  find . -type f | rev | sort | rev | sed "s/^/[ ] /g" > "$TARGETDIR/logs/unzip_file_checklist.txt"
  # Extract IPs
  echo "(UA) -> Extracting IPS"
  grep -RnEI ".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*" * > "$TARGETDIR/evidence/unzip_ips.txt"
  # Extract Email Addresses
  echo "(UA) -> Extracting Email Addresses"
  grep -RnEI ".*@.*\.com.*" * > "$TARGETDIR/evidence/unzip_emails.txt"
  # Extract Domains
  echo "(UA) -> Extracting Domain Names"
  grep -RnEI ".*\.com\".*" * > "$TARGETDIR/evidence/unzip_domains.txt"
  fgrep -RniI http * | grep -Eo 'http.*' | grep "://" | sort | uniq > "$TARGETDIR/evidence/unzip_http_domains.txt"
  # Extract Double Quoted Strings
  echo "(UA) -> Extracting Double Quoted Strings"
  grep -ERoI '".*"' * | grep -Eo '".*"' | cut -c2- | rev | cut -c2- | rev | sort | uniq > "$TARGETDIR/evidence/unzip_double_quoted_strings.txt"
  # Get 3rd party packages / libraries
  echo "(UA) -> Extracting Packages + Imports"
  grep -Rn "$TARGETDIR/unzip" -e "import" -e "package" | grep -Fv -e "package=" -e "package name=" -e "LICENSE" | cut -d ":" -f 2 | sort -u > "$TARGETDIR/evidence/unzip_imports.txt"
  cd $TARGETDIR
}


# Function calls / workflow
project_setup
decompiled_audit
unzipped_audit

#qark --apk $FILE > logs/qark_log.txt
#cp /usr/local/lib/python3.7/site-packages/qark/report/report.html evidence/qark_report.html

#z=`python /Users/jkitson/Tools/AndroBugs_Framework/androbugs.py -f $FILE | sed  's/<<< Analysis report is generated://g' | sed 's/ >>>//g'`
#echo $z
#cp $z evidence/androbugs_report.txt
