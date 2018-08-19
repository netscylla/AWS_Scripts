#!/bin/sh

ROLENAME=$(curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ -s)
KeyURL="http://169.254.169.254/latest/meta-data/iam/security-credentials/"$ROLENAME"/"
wget $KeyURL -q -O Iam.json
KEYID=$(grep -Po '.*"AccessKeyId".*' Iam.json | sed 's/ //g' | sed 's/"//g' | sed 's/,//g' | sed 's/AccessKeyId://g')
SECRETKEY=$(grep -Po '.*"SecretAccessKey".*' Iam.json | sed 's/ //g' | sed 's/"//g' | sed 's/,//g' | sed 's/SecretAccessKey://g')
SECURITYTOKEN=$(grep -Po '.*"Token".*' Iam.json | sed 's/ //g' | sed 's/"//g' | sed 's/,//g' | sed 's/Token://g')
rm Iam.json -f

echo $KEYID
echo $SECRETKEY
echo $SECURITYTOKEN
