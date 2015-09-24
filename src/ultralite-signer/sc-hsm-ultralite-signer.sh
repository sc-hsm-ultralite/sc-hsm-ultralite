#!/bin/bash

# This is a convenience script for running sc-hsm-ultralite-signer.
# 
# This script also automates (and speeds up) finding all files from 
# today and yesterday. It searches for all files matching the regex
# yyyy-mm-dd where yyyy-mm-dd is once today's date and once yesterday's 
# date. It only searches the sub-folder(s) matching the regex yyyy-mm 
# where yyyy-mm is once today's month and once yesterday's month. Note 
# yyyy-mm will always be the same folder for yesterday and today except 
# for the first day of any particular month.
# Uncomment the first "find" command below to make the script also
# search the base path itself (i.e. flat hierarchy).
# It skips hidden files (i.e. name begins with '.') and ".p7s" files.
#
# For example, consider the path d:\data with the following contents...
# + d:\data\2013-08
#   - ...
# + d:\data\2013-09
#   - xxxx-2013-09-01.dat
#   - ...
#   - xxxx-2013-09-30.dat
#   - xxxx-2013-09-30.dat.p7s
# + d:\data\2013-10
#   - xxxx-2013-10-01.dat
#   - xxxx-2013-10-01.log
#
# This script is executed with the following arguments...
# ./sc-hsm-ultralite-signer.sh 123456 sign0 /data
# 
# If today's date is 2013-10-01, the following commands will be executed...
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.dat
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.log
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-09\xxxx-2013-09-30.dat

# Verify arg count
if [[ $# -ne 3 ]]; then
    echo "Usage: <pin> <label> <base-path>"
    exit
fi

# Parse args
EXE=${0%.*} # strip extension
PIN=${1}
LABEL=${2}
BASE_PATH=${3%/} # strip trailing '/'

# Calculate path to current & previous month folder in format "YYYY-mm"
    CUR_DAY=$(date                            +%Y-%m-%d)
CUR_DAY_MTH=$(date --date="${CUR_DAY}"        +%Y-%m)
    PRV_DAY=$(date --date="${CUR_DAY} -1 day" +%Y-%m-%d)
PRV_DAY_MTH=$(date --date="${PRV_DAY}"        +%Y-%m)

# Run sc-hsm-ultralite-signer
# if [ -d ${BASE_PATH} ]; then
#    find ${BASE_PATH} -maxdepth 1 -type f \( -name \*${CUR_DAY}\* \! -name \*.p7s -or -name \*${PRV_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' ';'
# fi
if [ -d ${BASE_PATH}/${CUR_DAY_MTH} ]; then
    find ${BASE_PATH}/${CUR_DAY_MTH} -maxdepth 1 -type f \( -name \*${CUR_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' ';'
fi
if [ -d ${BASE_PATH}/${PRV_DAY_MTH} ]; then
    find ${BASE_PATH}/${PRV_DAY_MTH} -maxdepth 1 -type f \( -name \*${PRV_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' ';'
fi
