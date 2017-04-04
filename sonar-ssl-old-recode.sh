#!/bin/bash

HOMEDIR="/storage/praha1/home/${LOGNAME}"
cd $HOMEDIR

export MPICH_NEMESIS_NETMOD=tcp
export OMP_NUM_THREADS=$PBS_NUM_PPN
export PYENV_ROOT="${HOMEDIR}/.pyenv"
export PATH="${PYENV_ROOT}/bin:${PATH}"

# module add openmpi-2.0.1-intel
# module add openmpi-2.0.1-gcc
# module add openmpi

eval "$(pyenv init -)"
sleep 1

pyenv local 2.7.13
sleep 1

echo "`hostname` starting..."

exec stdbuf -eL python /storage/praha1/home/ph4r05/cas/codesign/censys_sonarssl.py \
    /storage/praha1/home/ph4r05/sonarssl/20131030-20150518_certs.gz \
    --datadir /storage/brno7-cerit/home/ph4r05/sonarssl \
    --json /storage/praha1/home/ph4r05/cas/tls_sonar.ssl.json 2> /storage/praha1/home/ph4r05/logs/recode.log

