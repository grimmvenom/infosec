#!/bin/bash

: <<'ENDBlock'
# Summary:
# ------------------------------
# Example: bash android_audit.sh ./demo.apk
#
# Create a project directory based on APK or IPA
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
Arg1="${1}"
if [[ "${2}" != "" ]]; then
  TARGETDIR="${2}"
else
  # Define Output Location
  TARGETDIR="$HOME/Downloads/Reports/$AppName-$DATE_$TIME"
fi
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

###############
# User Variables (May need Tweaking)
###############
# Define Directory where apks are stored
GODIR=$(realpath "$HOME/go/fandango/apks/")


function project_setup {
  echo -e "\nCreating Project Directories @ $TARGETDIR"
  # Create Directories if they don't exist
  mkdir -p $TARGETDIR/{"logs","evidence","jadx","unzip"}

  # Copy Application to Target Directory
  # cp "$GODIR/$FILE" $TARGETDIR"/"$FILE
  echo "Copying: ${Arg1}"
  cp "$Arg1" "$TARGETDIR/${FileName}"
}

function decompile_app {
  echo -e "\nDecompiled Application"
  echo -e "================================================\n"
  # Run JADX (decompile application) on Copied version of Application
  jadx -d "$TARGETDIR/jadx" "$TARGETDIR/$FILE" > "$TARGETDIR/logs/jadx_decompile_log.txt"
}

function decompiled_audit {
  echo -e "\nRunning Decompiled Audit"
  echo -e "================================================\n"
  cd "$TARGETDIR/jadx"
  # Extract Files as a checklist
  echo "(DA) -> Extracting Files As Checklist"
  find "${TARGETDIR}" -type f | rev | sort | rev | sed "s/^/[ ] /g" > "$TARGETDIR/logs/jadx_file_checklist.txt"
  # Extract IPs
  echo "(DA) -> Extracting IPS"
  grep -RnEI ".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*" "${TARGETDIR}/jadx" > "$TARGETDIR/evidence/jadx_ips.txt"
  # Extract email addresses
  echo "(DA) -> Extracting Email Addresses"
  grep -RnEI ".*@.*\.com.*" "${TARGETDIR}/jadx" > "$TARGETDIR/evidence/jadx_emails.txt"
  # Extract Domain Names
  echo "(DA) -> Extracting Domain Names"
  grep -RnEI ".*\.com\".*" "${TARGETDIR}/jadx" > "$TARGETDIR/evidence/jadx_domains.txt"
  fgrep -RniI http * | grep -Eo 'http.*' | grep "://" | sort | uniq > "$TARGETDIR/evidence/jadx_http_domains.txt"
  # Extract Double Quoted Strings
  echo "(DA) -> Extracting Double Quoted Strings"
  grep -ERoI '".*"' "${TARGETDIR}/jadx" | grep -Eo '".*"' | cut -c2- | rev | cut -c2- | rev | sort | uniq > "$TARGETDIR/evidence/jadx_double_quoted_strings.txt"
  # Get 3rd party packages / libraries
  echo "(DA) -> Extracting Packages + Imports"
  grep -Rn "${TARGETDIR}/jadx" -e "import" -e "package" | grep -Fv -e "package=" -e "package name=" -e "LICENSE" | cut -d ":" -f 2 | sort -u > "$TARGETDIR/evidence/jadx_imports.txt"
  cd $TARGETDIR
}

function unzip_app {
  echo -e "\UnZipping Application"
  echo -e "================================================\n"
  cd $TARGETDIR"/unzip"
  # Unzip application instead of decompile
  unzip "$TARGETDIR/"$FILE > "$TARGETDIR/logs/unzip_log.txt"
}

function unzipped_audit {
  rm "${TARGETDIR}/evidence/unzip*.txt"
  echo -e "\nRunning UnZipped Audit"
  echo -e "================================================\n"
  # Extract Files as a checklist
  echo "(UA) -> Extracting Files As Checklist"
  find "${TARGETDIR}/unzip" -type f | rev | sort | rev | sed "s/^/[ ] /g" > "$TARGETDIR/logs/unzip_file_checklist.txt"
  # Extract IPs
  echo "(UA) -> Extracting IPS"
  grep -RnEI ".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*" "${TARGETDIR}/unzip" > "$TARGETDIR/evidence/unzip_ips.txt"
  # Extract Email Addresses
  echo "(UA) -> Extracting Email Addresses"
  grep -RnEI ".*@.*\.com.*" "${TARGETDIR}/unzip" > "$TARGETDIR/evidence/unzip_emails.txt"
  # Extract Domains
  echo "(UA) -> Extracting Domain Names"
  grep -RnEI ".*\.com\".*" "${TARGETDIR}/unzip" > "$TARGETDIR/evidence/unzip_domains.txt"
  fgrep -RniI http "${TARGETDIR}/unzip" | grep -Eo 'http.*' | grep "://" | sort | uniq > "$TARGETDIR/evidence/unzip_http_domains.txt"
  # Extract Double Quoted Strings
  echo "(UA) -> Extracting Double Quoted Strings"
  grep -ERoI '".*"' "${TARGETDIR}/unzip" | grep -Eo '".*"' | cut -c2- | rev | cut -c2- | rev | sort | uniq > "$TARGETDIR/evidence/unzip_double_quoted_strings.txt"
  # Get 3rd party packages / libraries
  echo "(UA) -> Extracting Packages + Imports"
  grep -Rn "$TARGETDIR/unzip" -e "import" -e "package" | grep -Fv -e "package=" -e "package name=" -e "LICENSE" | cut -d ":" -f 2 | sort -u > "$TARGETDIR/evidence/unzip_imports.txt"
  cd $TARGETDIR
}

function check_binaries {
  rm "${TARGETDIR}/evidence/strings*.txt"
  IFS=$'\n'
  # binary_files=($(find "${TARGETDIR}" -type f -name "*.nib"))
  binary_files=($(find "${TARGETDIR}" -type f))
  plist_files=($(find "${TARGETDIR}" -type f -name "*.plist"))
  unset IFS
  printf "binary files found: "
  printf "${binary_files}"
  # for i in "${nib_files[@]:1:5}" # Range items 1-5
  for i in "${binary_files[@]}"
  do
    # Concatenate all strings output together into one easy to read file
    strings "${i}" >> "${TARGETDIR}/evidence/strings.txt"

    # Extract Files as a checklist
    echo "(strings) -> Extracting IPS from ${i}"
    strings "${i}" | grep -nEI ".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*" >> "${TARGETDIR}/evidence/unzip_ips.txt"

    # Extract Email Addresses
    echo "(strings) -> Extracting Email Addresses from ${i}"
    strings "${i}" | grep -nEI ".*@.*\.com.*" >> "$TARGETDIR/evidence/unzip_emails.txt"

    # Extract Domains
    echo "(strings) -> Extracting Domain Names from ${i}"
    strings "${i}" | grep -nEI ".*\.com\".*" >> "$TARGETDIR/evidence/unzip_domains.txt"
    fgrep -niI http "${i}" | grep -Eo 'http.*' | grep "://" | sort | uniq > "$TARGETDIR/evidence/unzip_http_domains.txt"

    # Extract Double Quoted Strings
    echo "(strings) -> Extracting Double Quoted Strings from ${i}"
    strings "${i}" | grep -EoI '".*"' | grep -Eo '".*"' | cut -c2- | rev | cut -c2- | rev | sort | uniq > "$TARGETDIR/evidence/unzip_double_quoted_strings.txt"

    # Get 3rd party packages / libraries
    echo "(strings) -> Extracting Packages + Imports from ${i}"
    strings "${i}" | grep -n -e "import" -e "package" | grep -Fv -e "package=" -e "package name=" -e "LICENSE" | cut -d ":" -f 2 | sort -u > "$TARGETDIR/evidence/unzip_imports.txt"

    printf "\n"
  done
}

function cleanup {
  printf "Cleaning up output\n"
  IFS=$'\n'
  output_files=($(find "${TARGETDIR}/evidence" -type f -name "*.txt"))
  unset IFS
  # for i in "${nib_files[@]:1:5}" # Range items 1-5
  for i in "${output_files[@]}"
  do
    printf "Output Cleanup -> ${i} \n"
    cat "${i}" | uniq | sort -k2 > "${i}"
  done
}


# Function calls / workflow
echo "Arg1: ${1}"
echo "DirPath: ${DirPath}"
echo "FileName: $FileName"
echo "AppName: ${AppName}"
echo "Extension: ${extension}"
echo "Report Directory: ${TARGETDIR}"
echo " "
case "${FILE}" in
  *".apk")
    echo -n "Project is an Android Application."
    if [ ! -z "${2}" ]; then
      if test -d "${TARGETDIR}"; then
        printf "NOT first run, using existing reports directory\n"
      else
        printf "${TARGETDIR} not found. Use existing report directory or run without report arugment"
        exit
      fi
    else
      project_setup
      decompile_app
      unzip_app
    fi

    decompiled_audit
    unzipped_audit
    cleanup
    ;;

  *".ipa")
    printf "Project is an IOS Application.\n"
    if [ ! -z "${2}" ]; then
      if test -d "${TARGETDIR}"; then
        printf "NOT first run, using existing reports directory\n"
      else
        printf "${TARGETDIR} not found. Use existing report directory or run without report arugment"
        exit
      fi

    else
      project_setup
      unzip_app
    fi

    unzipped_audit
    check_binaries
    cleanup
    ;;
esac
