#!/us/bin/python3
# Hunt Unristricted Egress to 0.0.0.0/0
# Licensed under GPL v3
# Copyright Netscylla

import boto3

session = boto3.Session(profile_name='temp')
client = session.client('ec2',region_name="eu-west-1")

sg_unrestricted = set(
  sg['GroupId']
  for sg in
  client.describe_security_groups(Filters=[{"Name": "egress.ip-permission.cidr", "Values": ["0.0.0.0/0"]}])['SecurityGroups']
)
print("Groups containing unrestricted Egress: ")
print(sg_unrestricted)

response = client.describe_instances(Filters=[{'Name':'instance.group-id','Values':list(sg_unrestricted)}])
for r in response['Reservations']:
  for i in r['Instances']:
    for n in i['NetworkInterfaces']:
      for x in n['Groups']:
        if x['GroupId'] in sg_unrestricted:
          if (len(i['InstanceId']) < 13):
            print("Found " + i['InstanceId'] + "\t : " + x['GroupId'] + " : ", end='')
          else:
            print("Found " + i['InstanceId'] + ": " + x['GroupId'] + " : ", end='')
    for a in i['Tags']:
      print(a['Value'])
