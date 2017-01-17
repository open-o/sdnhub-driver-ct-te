#!/bin/bash
#
#  Copyright 2016-2017 China Telecommunication Co., Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

BASEDIR=$(dirname $(readlink -f $0))

#
# Python
#
	
##
## Prepare
##

yum install -y wget

yum install -y epel-release
yum install -y python-pip

yum install -y libxml2
yum install -y libxslt

yum install -y libxslt-devel
yum install -y gcc 

yum install -y python-devel
yum install -y libffi
yum install -y libffi-devel
yum install -y openssl-devel 

pip install setuptools
   
##
## Ensure packages are latest version
##
# pip list | awk '{print $1}' | xargs pip install -U 
pip install -U setuptools

##
## Install ncclient
##

cd /tmp
wget https://github.com/ncclient/ncclient/tarball/master -O /tmp/ncclient.tar.gz
tar xvf /tmp/ncclient.tar.gz

FOLDERNAME=`tar tvf /tmp/ncclient.tar.gz  | head  -n 1 | awk '{print $NF}'`
cd $FOLDERNAME

python setup.py install 


##
## Others
##

pip install epydoc
pip install tornado
pip install bottle

# Download and install the swagger module
curl https://github.com/SerenaFeng/tornado-swagger/archive/master.zip -L -o /tmp/swagger.zip 
yum install -y unzip
rm -fr /tmp/swagger/
unzip /tmp/swagger.zip -d /tmp/swagger/
cd /tmp/swagger/tornado-swagger-master
python setup.py install
cd ${BASEDIR}


