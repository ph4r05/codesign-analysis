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
sleep 3

pyenv local 2.7.13
sleep 3

echo "`hostname` starting..."

mpirun -machinefile $PBS_NODEFILE \
/bin/bash /storage/praha1/home/ph4r05/cas/assets/meta-scripts/ee-fetch-submpi.sh "${SCRATCH}"

echo "Finished, fetching"
for srv in `cat $PBS_NODEFILE`; do
    echo "Fetching $srv"
    scp $srv:"${SCRATCH}/*" /storage/brno3-cerit/home/ph4r05/eeids-mpis
done


