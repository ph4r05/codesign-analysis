#!/bin/bash

while true; do

    python $*

    reset
    tput reset

    if [ -f ".github-quit" ]; then
        echo -e "\nQuit file found, terminating"
        exit
    fi

    echo -e "\n\nSleeping a bit..."
    sleep 10
    echo -e "\n"
done