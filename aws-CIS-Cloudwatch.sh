#!/bin/bash
#
# Simple script to setup Cloudwatch alarms for CIS AWS compliance 3.2-3.14
# Version 0.1 alpha
# (C) 2018 Netscylla
# WARNING! USE AT YOUR OWN RISK!
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# TODO CIS alarms for 3.1 & 3.7
#

#setup variables
email="example.com"
account="12345678"
region="eu-west-5"
logname="CloudTrail/CloudWatchLogGroup"

GREEN='\033[0;32m'
NC='\033[0m'

#setup SNS Topic
aws sns create-topic --name CloudWatchAlarmSNSTopic --region $region

aws sns subscribe \
--region $region \
--topic-arn arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic \
--protocol email \
--notification-endpoint $email

echo -e "[CHECK] Check your email, and click the link to activate the SNS Topic\n${NC}"

#set-up metric and alarms

#console sign in without mfa
echo -e "${GREEN}[3.2] A log metric filter and alarm for Management Console sign-in without MFA\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name ConsoleSignInWithoutMfaCount \
--filter-pattern '{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed = "No" }' \
--metric-transformations metricName=ConsoleSignInWithoutMfaCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name ConsoleSignInWithoutMfaAlarm \
--alarm-description "Triggered by sign-in requests made without MFA." \
--metric-name ConsoleSignInWithoutMfaCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#root alarm
echo -e "${GREEN}[3.3] A log metric filter and alarm for usage of root account\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name RootAccountUsage \
--filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
--metric-transformations metricName=RootAccountUsageEventCount,metricNamespace=CloudTrailMetrics,metricValue=1 

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name RootAccountUsageAlarm \
--alarm-description "Triggered by AWS Root Account usage." \
--metric-name RootAccountUsageEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#iam policy changes
echo -e "${GREEN}[3.4] A log metric filter and alarm for IAM policy changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name IAMAuthConfigChanges \
--filter-pattern '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }' \
--metric-transformations metricName=IAMPolicyEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name IAMAuthorizationActivityAlarm \
--alarm-description "Triggered by AWS IAM authorization config changes." \
--metric-name IAMPolicyEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#cloudtrail changes
echo -e "${GREEN}[3.5] A log metric filter and alarm for CloudTrail configuration changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name AWSCloudTrailChanges \
--filter-pattern ' { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }' \
--metric-transformations metricName=CloudTrailEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name "CloudTrail Changes" \
--alarm-description "Triggered by AWS CloudTrail configuration changes." \
--metric-name CloudTrailEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#console auth failures
echo -e "${GREEN}[3.6] A log metric filter and alarm for AWS Management Console authentication failures\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name AWSConsoleSignInFailures \
--filter-pattern '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }' \
--metric-transformations metricName=ConsoleSigninFailureCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name "Console Sign-in Failures" \
--alarm-description "AWS Management Console Sign-in Failure Alarm." \
--metric-name ConsoleSigninFailureCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 3 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#s3 bucket policy changes
echo -e "${GREEN}[3.8] A log metric filter and alarm  for S3 bucket policy changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name S3BucketConfigChanges \
--filter-pattern '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }' \
--metric-transformations metricName=S3BucketEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name S3BucketConfigChangesAlarm \
--alarm-description "Triggered by AWS S3 Bucket config changes." \
--metric-name S3BucketEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \ 
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#config changes
echo -e "${GREEN}[3.9] log metric filter and alarm for AWS Config configuration changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name AWSConfigChanges \
--filter-pattern '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder)||($.eventName = DeleteDeliveryChannel)||($.eventName = PutDeliveryChannel)||($.eventName = PutConfigurationRecorder)) }' \
--metric-transformations metricName=ConfigEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name AWSConfigChangesAlarm \
--alarm-description "Triggered by AWS Config changes." \
--metric-name ConfigEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#security group changes
echo -e "${GREEN}[3.10] A log metric filter and alarm for security group changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name SecurityGroupConfigChanges \
--filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }' \
--metric-transformations metricName=SecurityGroupEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name SecurityGroupConfigChangesAlarm \
--alarm-description "Triggered by AWS security group(s) config changes." \
--metric-name SecurityGroupEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \ 
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#nacl changes
echo -e "${GREEN}[3.11] A log metric filter and alarm for changes to Network Access Control Lists (NACL)\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name NetworkACLConfigChanges \
--filter-pattern '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }' \
--metric-transformations metricName=NetworkAclEventCount,metricNamespace=CloudTrailMetrics,metricValue=1 

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name NetworkACLConfigChangesAlarm \
--alarm-description "Triggered by AWS Network ACL(s) config changes." \
--metric-name NetworkAclEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#network gateway changes
echo -e "${GREEN}[3.12] A log metric filter and alarm for changes to network gateways\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name VPCGatewayConfigChanges \
--filter-pattern '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }' \
--metric-transformations metricName=GatewayEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name VPCGatewayConfigChangesAlarm \
--alarm-description "Triggered by VPC Customer/Internet Gateway changes." \
--metric-name GatewayEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#route table changes
echo -e "${GREEN}[3.13] A log metric filter and alarm for route table changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name RouteTableConfigChanges \
--filter-pattern '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }' \
--metric-transformations metricName=RouteTableEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name RouteTableConfigChangesAlarm \
--alarm-description "Triggered by AWS Route Table config changes." \
--metric-name RouteTableEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic

#vpc changes
echo -e "${GREEN}[3.14] A log metric filter and alarm for VPC changes\n${NC}"
aws logs put-metric-filter \
--region $region \
--log-group-name $logname \
--filter-name VPCNetworkConfigChanges \
--filter-pattern '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }' \
--metric-transformations metricName=VpcEventCount,metricNamespace=CloudTrailMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
--region $region \
--alarm-name VPCNetworkConfigChangesAlarm \
--alarm-description "Triggered by AWS VPC(s) environment config changes." \
--metric-name VpcEventCount \
--namespace CloudTrailMetrics \
--statistic Sum \
--comparison-operator GreaterThanOrEqualToThreshold \
--evaluation-periods 1 \
--period 300 \
--threshold 1 \
--actions-enabled \
--alarm-actions arn:aws:sns:$region:$account:CloudWatchAlarmSNSTopic
