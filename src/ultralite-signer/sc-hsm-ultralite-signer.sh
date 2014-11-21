#!/bin/bash

# This is a convenience script for running sc-hsm-ultralite-signer.
# 
# This script implements rotating logs for capturing the stdout
# and stderr info/warning/error messages. Each log is rotated after
# the size of the log exceeds LOGSIZE_MAX. Two backups are kept.
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
# ./sc-hsm-ultralite-signer.sh out.log err.log 123456 sign0 /data
# 
# If today's date is 2013-10-01, the following commands will be executed...
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.dat >> out.log 2>> err.log
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-10\xxxx-2013-10-01.log >> out.log 2>> err.log
# ./sc-hsm-ultralite-signer 123456 sign0 d:\data\2013-09\xxxx-2013-09-30.dat >> out.log 2>> err.log

LOGSIZE_MAX=0x100000

# Verify arg count
if [[ $# -ne 5 ]]; then
    echo "Usage: <stdout-log> <stderr-log> <pin> <label> <base-path>"
    exit
fi

# Parse args
EXE=${0%.*} # strip extension
OUT_LOG=${1}
ERR_LOG=${2}
PIN=${3}
LABEL=${4}
BASE_PATH=${5%/} # strip trailing '/'

# Verify args
if [[ -a ${OUT_LOG} && -x ${OUT_LOG} ]]; then
    echo "ERROR: Argument 1 (${OUT_LOG}) must not be executable."
    exit
fi
if [[ -a ${ERR_LOG} && -x ${ERR_LOG} ]]; then
    echo "ERROR: Argument 2 (${ERR_LOG}) must not be executable."
    exit
fi

# Rotate the stdout log if it's current size is greater than LOGSIZE_MAX
if [ -f ${OUT_LOG} ]; then
    LOGSIZE=$(stat -c%s "${OUT_LOG}" 2> /dev/null)
    if [[ ${LOGSIZE:=0} -ge ${LOGSIZE_MAX} ]]; then
	mv "${OUT_LOG}.1" "${OUT_LOG}.2" > /dev/null 2>&1
	mv "${OUT_LOG}" "${OUT_LOG}.1" > /dev/null 2>&1
    fi
fi
    
# Rotate the stderr log if it's current size is greater than LOGSIZE_MAX
if [ -f ${ERR_LOG} ]; then
    LOGSIZE=$(stat -c%s "${ERR_LOG}" 2> /dev/null)
    if [[ ${LOGSIZE:=0} -ge ${LOGSIZE_MAX} ]]; then
	mv "${ERR_LOG}.1" "${ERR_LOG}.2" > /dev/null 2>&1
	mv "${ERR_LOG}" "${ERR_LOG}.1" > /dev/null 2>&1
    fi
fi
    
# Calculate path to current & previous month folder in format "YYYY-mm"
    CUR_DAY=$(date                            +%Y-%m-%d)
CUR_DAY_MTH=$(date --date="${CUR_DAY}"        +%Y-%m)
    PRV_DAY=$(date --date="${CUR_DAY} -1 day" +%Y-%m-%d)
PRV_DAY_MTH=$(date --date="${PRV_DAY}"        +%Y-%m)

# Run sc-hsm-ultralite-signer and log stdout/stderr to the respective logs
# if [ -d ${BASE_PATH} ]; then
#    find ${BASE_PATH} -maxdepth 1 -type f \( -name \*${CUR_DAY}\* \! -name \*.p7s -or -name \*${PRV_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' >> ${OUT_LOG} 2>> ${ERR_LOG} ';'
# fi
if [ -d ${BASE_PATH}/${CUR_DAY_MTH} ]; then
    find ${BASE_PATH}/${CUR_DAY_MTH} -maxdepth 1 -type f \( -name \*${CUR_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' >> ${OUT_LOG} 2>> ${ERR_LOG} ';'
fi
if [ -d ${BASE_PATH}/${PRV_DAY_MTH} ]; then
    find ${BASE_PATH}/${PRV_DAY_MTH} -maxdepth 1 -type f \( -name \*${PRV_DAY}\* \! -name \*.p7s \) -exec ${EXE} ${PIN} ${LABEL} '{}' >> ${OUT_LOG} 2>> ${ERR_LOG} ';'
fi
 
