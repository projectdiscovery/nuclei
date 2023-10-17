#!/bin/bash

# This script is used to retry failed workflows in github actions.
# It uses gh cli to fetch the failed workflows and then rerun them.
# It also checks the logs of the failed workflows to see if it is a flaky test.
# If it is a flaky test, it will rerun the failed jobs in the workflow.
# eg:
# ./gh_retry.sh -h to see the help.
# ./gh_retry.sh will run the script with default values. 

# You can also pass the following arguments:
# ./gh_retry.sh -b master -l 30 -t "30 mins ago" -w "Build Test"

#Initialize variables to default values.
BRANCH=$(git symbolic-ref --short HEAD)
LIMIT=30
BEFORE="30 mins ago"
WORKFLOW="Build Test"

# You can add multiple patterns separated by |
GREP_ERROR_PATTERN='Test "http/interactsh.yaml" failed'

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
   echo "${REV}-t${NORM}  Time to filter the failed jobs. Default is ${BOLD}$BEFORE${NORM}."
   echo "${REV}-w${NORM}  Workflow to filter the failed jobs. Default is ${BOLD}$WORKFLOW${NORM}."
   echo
}

while getopts :b:l:t:w:h FLAG; do
  case $FLAG in
    b)
      BRANCH=$OPTARG
      ;;
    l)
      LIMIT=$OPTARG
      ;;
    t)
      BEFORE=$OPTARG
      ;;
    w)
      WORKFLOW=$OPTARG
      ;;
    h) #show help
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

function print_bold() {
    echo "${BOLD}$1${NORM}"
}

function retry_failed_jobs() {
    print_bold "Checking failed workflows for branch $BRANCH before $BEFORE"

    date=`date +%Y-%m-%d'T'%H:%M'Z' -d "$BEFORE"`

    workflowIds=$(gh run list --limit "$LIMIT"  --json headBranch,status,name,conclusion,databaseId,updatedAt | jq -c '.[] |
    select ( .headBranch==$branch ) |
    select ( .name | contains($workflow) ) |
    select ( .conclusion=="failure" ) |
    select ( .updatedAt > $date) ' --arg date "$date" --arg branch "$BRANCH" --arg workflow "$WORKFLOW" | jq .databaseId)

    # convert line separated by space to array
    eval "arr=($workflowIds)"

    if [[ -z $arr ]]
    then
        print_bold "Could not find any failed workflows in the last $BEFORE"
        exit 0
    fi

    for s in "${arr[@]}"; do
        print_bold "Checking logs of failed workflow $s to see if it is a flaky test"
        gh run view "$s" --log-failed | grep -E "$GREP_ERROR_PATTERN" > /dev/null
        if [ $? == 0 ] ; then
            print_bold "Retrying failed jobs $s"
            gh run rerun "$s" --failed
            sleep 10s
            gh run view "$s"
        fi
    done
}

retry_failed_jobs
