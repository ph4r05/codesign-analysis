#!/bin/bash

DATADIR="/storage/praha1/home/$LOGNAME/results"
mkdir -p $DATADIR

HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR



qsub -l select=1:ncpus=1:mem=1gb:scratch_local=1gb -l walltime=48:00:00 censys_tls_01.sh

