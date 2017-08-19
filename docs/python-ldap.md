# Installing python-ldap

Ubuntu:
```
sudo apt-get install python-pip python-dev libmysqlclient-dev
sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
```

CentOS:
```
sudo yum install python python-devel mysql-devel redhat-rpm-config gcc
sudo yum install python-devel openldap-devel
```

## Metacentrum - non-root install

Build static library:

http://www.linuxfromscratch.org/blfs/view/cvs/server/openldap.html

Copy include and libs to ~/libs

```
pip install --global-option=build_ext --global-option="-I/storage/praha1/home/ph4r05/libs/include/" --global-option="-L/storage/praha1/home/ph4r05/libs/lib/x86_64-linux-gnu"   python-ldap
```

## Meta deb packages

```
apt-get download libargtable2-0

ar -x libargtable2-0_12-1.1_amd64.deb; ls

unxz data.tar.xz
tar -xvf data.tar

cp ./usr/lib/libargtable2.so.0* /where/needed
```


