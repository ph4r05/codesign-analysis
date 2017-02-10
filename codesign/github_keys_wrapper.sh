#!/bin/bash

while true; do

    python $*

    reset
    tput reset

    echo -e "\n\nSleeping a bit..."
    sleep 10
    echo -e "\n"
done