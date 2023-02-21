#!/bin/bash 

retry() {
    local -r -i max_attempts="$1"; shift
    local -i attempt_num=1
    local -r -i sleep_seconds=30
    until "$@"
    do
        if ((attempt_num==max_attempts))
        then
            echo "Attempt $attempt_num failed and there are no more attempts left!"
            return 1
        else
            echo "Attempt $attempt_num failed! Trying again in $sleep_seconds seconds..."
            ((attempt_num++))
            sleep $sleep_seconds
        fi
    done
}

"$@"
