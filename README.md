# Codesign analysis

# Experiments

## Generate TLS fetch

```
export DATADIR="/storage/praha1/home/$LOGNAME/results"
mkdir -p $DATADIR

export HOMEDIR="/storage/praha1/home/$LOGNAME"
cd $HOMEDIR
mkdir jobs
cd jobs

python ../cas/codesign/censys_gen_jobs.py --home=$HOMEDIR --data=$DATADIR --wrapper ${HOMEDIR}/cas/censys_tls_wrapper.sh ${HOMEDIR}/cas/tls_ipv4_history.json
```

## Local install

```
pip install --upgrade --find-links=. .
```

## Dependencies

```
pip install MySql-Python
pip install SQLAlchemy
```

Ubuntu:
```
sudo apt-get install python-pip python-dev libmysqlclient-dev
```

CentOS:
```
sudo yum install python python-devel mysql-devel redhat-rpm-config gcc
```

## Scipy installation with pip

```
pip install pyopenssl
pip install pycrypto
pip install git+https://github.com/scipy/scipy.git
pip install --upgrade --find-links=. .
```

## Virtual environment

It is usually recommended to create a new python virtual environment for the project:

```
virtualenv ~/pyenv
source ~/pyenv/bin/activate
pip install --upgrade pip
pip install --upgrade --find-links=. .
```

## Aura / Aisa on FI MU

```
module add cmake-3.6.2
module add gcc-4.8.2
```

## Python 2.7.13

It won't work with lower Python version. Use `pyenv` to install a new Python version.
It internally downloads Python sources and installs it to `~/.pyenv`.

```
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec $SHELL
pyenv install 2.7.13
pyenv local 2.7.13
```

