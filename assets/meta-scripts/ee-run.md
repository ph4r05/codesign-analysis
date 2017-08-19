## Paralel run

```
qsub -l select=32:ncpus=1:mem=200mb:scratch_local=200mb -l walltime=00:59:00 -l place=scatter -I
```

To exclude previously used cluster (and now depleted):

```
qsub -l select=32:ncpus=1:mem=200mb:scratch_local=200mb:cl_luna=False -l walltime=00:59:00 -l place=scatter -I
```

## Locality sync

```
rsync -av ../codesign-analysis/ tarkil:~/cas/ && \
rsync -av ../codesign-analysis/ tarkil:/storage/plzen1/home/ph4r05/cas/ && \
rsync -av ../codesign-analysis/ tarkil:/storage/brno2/home/ph4r05/cas/
```

## Collect results to one file

```
./ee-consolidate.sh /storage/brno3-cerit/home/ph4r05/eeids-mpis
```

## Download the final product

```
scp tarkil:/storage/brno3-cerit/home/ph4r05/eeids-total/eeids_total.json eeids_tarkil.json
```

## Setup

For the correct operation one has to have working environment on all localities.
One simple way to achieve that is to have one primary and then sync to others.

```
rsync -av /storage/praha1/home/ph4r05/.pyenv /storage/praha1/home/ph4r05/libs /storage/brno2/home/ph4r05/
rsync -av /storage/praha1/home/ph4r05/.pyenv /storage/praha1/home/ph4r05/libs /storage/plzen1/home/ph4r05/
```

