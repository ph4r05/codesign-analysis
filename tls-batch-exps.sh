#!/bin/bash

DATADIR="/storage/praha1/home/$LOGNAME/results"
mkdir -p $DATADIR

HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR


qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00011.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00020.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00030.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00040.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00050.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00060.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00070.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00080.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00090.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00100.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00110.sh
qsub -l select=1:ncpus=1:mem=800mb:scratch_local=1gb -l walltime=24:00:00 ${HOMEDIR}/jobs/fullipv4-00120.sh

