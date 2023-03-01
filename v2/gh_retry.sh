#!/bin/bash

#Initialize variables to default values.
BRANCH=$(git symbolic-ref --short HEAD)
LIMIT=300
BEFORE="30 mins ago"

#Set fonts for Help.
NORM=`tput sgr0`
BOLD=`tput bold`
REV=`tput smso`

HELP()
{
   # Display Help
   echo "Script to retry failed workflows in github actions."
   echo
   echo "Syntax: scriptTemplate [-b]"
   echo "options:"
   echo "${REV}-b${NORM}  Branch to check failed workflows/jobs. Default is ${BOLD}$BRANCH${NORM}."
   echo "${REV}-l${NORM}  Maximum number of runs to fetch. Default is ${BOLD}$LIMIT${NORM}."
   echo "${REV}-t${NORM}  Time to filter the failed jobs . Default is ${BOLD}$BEFORE${NORM}."
   echo
}

while getopts :b:l:t:h FLAG; do
  case $FLAG in
    b)  #set option "b"
      BRANCH=$OPTARG
      ;;
    l)  #set option "c"
      LIMIT=$OPTARG
      ;;
    t)  #set option "d"
      BEFORE=$OPTARG
      ;;
    h)  #show help
      HELP
      exit 0
      ;;
    \?) #unrecognized option - show help
      echo -e \\n"Option -${BOLD}$OPTARG${NORM} not allowed."
      HELP
      exit 0
      ;;
  esac
done
shift $((OPTIND-1))

echo "Checking failed workflows for branch $BRANCH before $BEFORE"

date=`date +%Y-%m-%d'T'%H:%M'Z' -d "$BEFORE"`

workflowIds=$(gh run list --limit "$LIMIT"  --json headBranch,status,name,conclusion,databaseId,updatedAt | jq -c '.[] |
select ( .headBranch==$branch ) |
select ( .name | contains("Build Test") ) |
select ( .conclusion=="failure" ) |
select ( .updatedAt > $date) ' --arg date "$date" --arg branch "$BRANCH" | jq .databaseId)

# convert line seperated by space to array
eval "arr=($workflowIds)"

if [[ !${arr[@]} ]]
then
    echo "Could not find any failed workflows in the last $before"
fi

for s in "${arr[@]}"; do
    echo "Retrying worklflow failed jobs $s"
    gh run rerun "$s" --failed
    sleep 10s
    gh run view "$s"
done
