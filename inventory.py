# Original Source/Reference: https://github.com/janiko71/aws-inventory
# August 2021

# Python imports
import boto3
from botocore.exceptions import EndpointConnectionError, ClientError
import botocore
import collections
import csv
import json

import smtplib
import os, hmac, hashlib, sys
import pprint
import logging
from sys import exit
import time

import res.utils as utils
import config

# AWS Services imports
import res.glob         as glob

import res.compute      as compute
import res.storage      as storage
import res.db           as db
import res.dev          as dev
import res.iam          as iam
import res.network      as net
import res.fact         as fact
import res.security     as security
import res.analytics    as analytics
import res.management   as mgn
import res.business     as bus
import res.integration  as integ
import res.awsthread    as awsthread


# --- Argumentation. See function check_arguments.
#
# If we find log level parameter, we adjust log level.
# If we find no service name, we inventory all services.
# Else we only inventory services passed in cmd line.

profile_name, arguments, boto3_config = utils.check_arguments(sys.argv[1:])
nb_arg = len(arguments)

# if no arguments, we try all AWS services
if (nb_arg == 0):
    arguments = config.SUPPORTED_COMMANDS
    arguments.remove('ce')  # For it's not free, cost explorer is removed from defaults inventory. You need to call it explicitly.

# --- Displaying execution parameters
print('-'*100)
print ('Number of services   :', len(arguments))
print ('Services List        :', str(arguments))
print('-'*100)
print('Some the services listed above may be commented out in the inventory.py script.')
print()


# --- AWS basic information

ownerId = utils.get_ownerID(profile_name)
config.logger.info('OWNER ID: ' + ownerId)
config.logger.info('AWS Profile: ' + str(profile_name))


# --- AWS Regions

config.regions = utils.get_aws_regions(profile_name)
config.nb_regions = len(config.regions)


# --- Inventory initialization

inventory = {}
inv_ec2 = {}
inv_ec2_network_interfaces = {}
inv_ec2_ebs = {}
inv_ec2_vpcs = {}
inv_ec2_security_groups = {}
inv_ec2_internet_gateways = {}
inv_ec2_nat_gateways = {}
inv_ec2_subnets = {}
inv_ec2_eips = {}
inv_ec2_egpu = {}
inv_lambda = {}
inv_elastic = {}
inv_ecs = {}
inv_lightsail = {}
inv_autoscaling = {}
inv_eks = {}
inv_batch = {}
# Storage
inv_efs = {}
inv_glacier = {}
inv_storagegateway = {}
# Databases
inv_rds = {}
inv_dynamodb = {}
inv_neptune = {}
inv_redshift = {}
inv_elasticache = {}
# s3
inv_s3 = {}

# --- Progression counter initialization

config.nb_units_done = 0
for svc in arguments:
    config.nb_units_todo += (config.nb_regions * config.SUPPORTED_INVENTORIES[svc])


#
# Let's rock'n roll
#

thread_list = []

# Execution time, for information
t0 = time.time()


#################################################################
#                           COMPUTE                             #
#################################################################
#
# ----------------- EC2
#

if ('ec2' in arguments):
    thread_list.append(awsthread.AWSThread("ec2", compute.get_ec2_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-network-interfaces", compute.get_interfaces_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-vpcs", compute.get_vpc_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-ebs", compute.get_ebs_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-security-groups", compute.get_sg_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-internet-gateways", compute.get_igw_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-nat-gateways", compute.get_ngw_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-subnets", compute.get_subnet_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-eips", compute.get_eips_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ec2-egpus", compute.get_egpus_inventory, ownerId, profile_name))

#
# ----------------- Lambda functions
#

if ('lambda' in arguments):
    thread_list.append(awsthread.AWSThread("lambda", compute.get_lambda_inventory, ownerId, profile_name))
#
# #
# # ----------------- Elastic beanstalk
# #
if ('elasticbeanstalk' in arguments):
    thread_list.append(awsthread.AWSThread("elasticbeanstalk-environments", compute.get_elasticbeanstalk_environments_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("elasticbeanstalk-applications", compute.get_elasticbeanstalk_applications_inventory, ownerId, profile_name))

# #
# # ----------------- ECS
# #
if ('ecs' in arguments):
    thread_list.append(awsthread.AWSThread("ecs-clusters", compute.get_ecs_inventory, ownerId, profile_name))
    thread_list.append(awsthread.AWSThread("ecs-tasks", compute.get_ecs_tasks_inventory, ownerId, profile_name))
#
# #
# # ----------------- Lighstail instances
# #
if ('lightsail' in arguments):
    thread_list.append(awsthread.AWSThread('lightsail', compute.get_lightsail_inventory, ownerId, profile_name))

# #
# # ----------------- Autoscaling
# #
if ('autoscaling' in arguments):
    thread_list.append(awsthread.AWSThread('autoscaling', compute.get_autoscaling_inventory, ownerId, profile_name))

# #
# # ----------------- EKS inventory
# #
if ('eks' in arguments):
    thread_list.append(awsthread.AWSThread('eks',compute.get_eks_inventory, ownerId, profile_name))

# #
# # ----------------- Batch jobs inventory
# #
if ('batch' in arguments):
    thread_list.append(awsthread.AWSThread('batch', compute.get_batch_inventory, ownerId, profile_name))

#
# #################################################################
# #                           STORAGE                             #
# #################################################################
# #
# # ----------------- EFS inventory
# #
if ('efs' in arguments):
    thread_list.append(awsthread.AWSThread('efs', storage.get_efs_inventory, ownerId, profile_name))

# #
# # ----------------- Glacier inventory
# #
if ('glacier' in arguments):
    thread_list.append(awsthread.AWSThread('glacier', storage.get_glacier_inventory, ownerId, profile_name))

# #
# # ----------------- Storage gateway inventory
# #
if ('storagegateway' in arguments):
    thread_list.append(awsthread.AWSThread('storagegateway', storage.get_storagegateway_inventory, ownerId, profile_name))

#
# #################################################################
# #                          DATABASES                            #
# #################################################################
# #
# # ----------------- RDS inventory
# #
if ('rds' in arguments):
    thread_list.append(awsthread.AWSThread('rds', db.get_rds_inventory, ownerId, profile_name))

# #
# # ----------------- dynamodb inventory
# #
if ('dynamodb' in arguments):
    thread_list.append(awsthread.AWSThread('dynamodb', db.get_dynamodb_inventory, ownerId, profile_name))

# #
# # ----------------- Neptune inventory
# #
if ('neptune' in arguments):
    thread_list.append(awsthread.AWSThread('neptune', db.get_neptune_inventory, ownerId, profile_name))

# #
# # ----------------- Redshift inventory
# #
if ('redshift' in arguments):
    thread_list.append(awsthread.AWSThread('redshift', db.get_redshift_inventory, ownerId, profile_name))

# #
# # ----------------- Elasticache inventory
# #
if ('elasticache' in arguments):
    thread_list.append(awsthread.AWSThread('elasticache', db.get_elasticache_inventory, ownerId, profile_name))

#
# #################################################################
# #                      SECURITY & IAM                           #
# #################################################################
# #
# # ----------------- KMS inventory
# #
# if ('kms' in arguments):
#     thread_list.append(awsthread.AWSThread('kms', iam.get_kms_inventory, ownerId, profile_name))
#
# #
# # ----------------- Cloud directory
# #
# if ('clouddirectory' in arguments):
#     thread_list.append(awsthread.AWSThread('clouddirectory', security.get_clouddirectory_inventory, ownerId, profile_name))
#
# #
# # ----------------- ACM (Certificates) inventory
# #
# if ('acm' in arguments):
#     thread_list.append(awsthread.AWSThread('acm', security.get_acm_inventory, ownerId, profile_name))
#
# #
# # ----------------- ACMPCA (Certificates) inventory Private Certificate Authority
# #
# if ('acm-pca' in arguments):
#     thread_list.append(awsthread.AWSThread('acm-pca', security.get_acm_inventory, ownerId, profile_name))
#
# #
# # ----------------- Secrets Manager
# #
# if ('secrets' in arguments):
#     thread_list.append(awsthread.AWSThread('secrets', security.get_secrets_inventory, ownerId, profile_name))
#
# #
# # ----------------- Cloud HSM
# #
# if ('hsm' in arguments):
#     thread_list.append(awsthread.AWSThread('hsm', security.get_hsm_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                      DEVELOPER TOOLS                          #
# #################################################################
# #
# # ----------------- CodeStar inventory
# #
# if ('codestar' in arguments):
#     thread_list.append(awsthread.AWSThread('codestar', dev.get_codestar_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                        INTEGRATION                            #
# #################################################################
# #
# # ----------------- Simple Queue Service inventory
# #
# if ('sqs' in arguments):
#     thread_list.append(awsthread.AWSThread('sqs', integ.get_sqs_inventory, ownerId, profile_name))
#
# #
# # ----------------- Amazon MQ inventory
# #
# if ('mq' in arguments):
#     thread_list.append(awsthread.AWSThread('mq', integ.get_mq_inventory, ownerId, profile_name))
#
# #
# # ----------------- Simple Notification Serv ice inventory
# #
# if ('sns' in arguments):
#     thread_list.append(awsthread.AWSThread('sns', integ.get_sns_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                         ANALYTICS                             #
# #################################################################
# #
# # ----------------- ElasticSearch
# #
# if ('es' in arguments):
#     thread_list.append(awsthread.AWSThread('es', analytics.get_es_inventory, ownerId, profile_name))
#
# #
# # ----------------- Cloudsearch
# #
# if ('cloudsearch' in arguments):
#     thread_list.append(awsthread.AWSThread('cloudsearch', analytics.get_cloudsearch_inventory, ownerId, profile_name))
#
# #
# # ----------------- Data Pipeline
# #
# if ('datapipeline' in arguments):
#     thread_list.append(awsthread.AWSThread('datapipeline', analytics.get_datapipeline_inventory, ownerId, profile_name))
#
# #
# # ----------------- Elastic MapReduce
# #
# if ('emr' in arguments):
#     thread_list.append(awsthread.AWSThread('emr', analytics.get_emr_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                         MANAGEMENT                            #
# #################################################################
# #
# # ----------------- CloudFormation
# #
# if ('cloudformation' in arguments):
#     thread_list.append(awsthread.AWSThread('cloudformation', mgn.get_cloudformation_inventory, ownerId, profile_name))
#
# #
# # ----------------- CloudTrail
# #
# if ('cloudtrail' in arguments):
#     thread_list.append(awsthread.AWSThread('cloudtrail', mgn.get_cloudtrail_inventory, ownerId, profile_name))
#
# # ----------------- CloudWatch
# #
# if ('cloudwatch' in arguments):
#     thread_list.append(awsthread.AWSThread('cloudwatch', mgn.get_cloudwatch_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                          NETWORK                              #
# #################################################################
# #
# # ----------------- API Gateway inventory
# #
# if ('apigateway' in arguments):
#     thread_list.append(awsthread.AWSThread('apigateway', net.get_apigateway_inventory, ownerId, profile_name))
#
# #
# # ----------------- Route 53 inventory
# #
# if ('route53' in arguments):
#     thread_list.append(awsthread.AWSThread('route53', net.get_route53_inventory, ownerId, profile_name))
#
# #
# # ----------------- CloudFront inventory
# #
# if ('cloudfront' in arguments):
#     thread_list.append(awsthread.AWSThread('cloudfront', net.get_cloudfront_inventory, ownerId, profile_name))
#
# #
# # ----------------- Load Balancer inventory
# #
# if ('elb' in arguments):
#     thread_list.append(awsthread.AWSThread('elb', net.get_elb_inventory, ownerId, profile_name))
#
# #
# # ----------------- Load Balancer v2 inventory
# #
# if ('elbv2' in arguments):
#     thread_list.append(awsthread.AWSThread('elbv2', net.get_elbv2_inventory, ownerId, profile_name))
#
#
# #################################################################
# #                   BUSINESS PRODUCTIVITY                       #
# #################################################################
# #
# # ----------------- Alexa for Business
# #
# if ('alexa' in arguments):
#     thread_list.append(awsthread.AWSThread('alexa', bus.get_alexa_inventory, ownerId, profile_name))
#
# #
# # ----------------- WorkDocs (not implemented)
# #
# if ('workdocs' in arguments):
#     thread_list.append(awsthread.AWSThread('workdocs', bus.get_workdocs_inventory, ownerId, profile_name))
#
# #
# # ----------------- Workmail (not well tested, some rights issues)
# #
# if ('workmail' in arguments):
#     thread_list.append(awsthread.AWSThread('workmail', bus.get_workmail_inventory, ownerId, profile_name))
#
# #
# # ----------------- Cost Explorer (experimental)
# #
# if ('ce' in arguments):
#     ce_inventory = []
#     """utils.display(ownerId, 'global', "cost explorer inventory", "")
#     list_ce = fact.get_ce_inventory(ownerId, None).get('ResultsByTime')
#     for item in list_ce:
#         ce_inventory.append(json.loads(utils.json_datetime_converter(item)))
#     inventory['cost-explorer'] = ce_inventory"""


#################################################################
#               International Resources (no region)             #
#################################################################

region_name = 'global'

#
# ----------------- S3 quick inventory
#
if ('s3' in arguments):
    thread_list.append(awsthread.AWSThread('s3', storage.get_s3_inventory, ownerId, profile_name))



# -------------------------------------------------------------------
#
#                         Thread management
#
# -------------------------------------------------------------------

for th in thread_list:
    th.start()

for th in thread_list:
    th.join()

#
# ----------------- Gathering all inventories
#
for svc in arguments:

    # Some particular cases
    if (svc == "ec2"):
        inv_ec2["ec2"] = config.global_inventory["ec2"]
        inv_ec2_network_interfaces["ec2-network-interfaces"] = config.global_inventory["ec2-network-interfaces"]
        inv_ec2_ebs["ec2-ebs"] = config.global_inventory["ec2-ebs"]
        inv_ec2_vpcs["ec2-vpcs"] = config.global_inventory["ec2-vpcs"]
        inv_ec2_security_groups["ec2-security-groups"] = config.global_inventory["ec2-security-groups"]
        inv_ec2_internet_gateways["ec2-internet-gateways"] = config.global_inventory["ec2-internet-gateways"]
        inv_ec2_nat_gateways["ec2-nat-gateways"] = config.global_inventory["ec2-nat-gateways"]
        inv_ec2_subnets["ec2-subnets"] = config.global_inventory["ec2-subnets"]
        inv_ec2_eips["ec2-eips"] = config.global_inventory["ec2-eips"]
        inv_ec2_egpu["ec2-egpu"] = config.global_inventory["ec2-egpus"]
    elif (svc == "ecs"):
        inv_ecs["ecs"] = {
            "ecs-clusters": config.global_inventory["ecs-clusters"],
            "ecs-tasks": config.global_inventory["ecs-tasks"]
        }
    elif (svc == "elasticbeanstalk"):

        inv_elastic["elasticbeanstalk"] = {
            "elasticbeanstalk-environments": config.global_inventory["elasticbeanstalk-environments"],
            "elasticbeanstalk-applications": config.global_inventory["elasticbeanstalk-applications"]
        }
    else:
        # General case(s)
        # Lambda
        if 'lambda' in config.global_inventory:
            inv_lambda["lambda"] = config.global_inventory["lambda"]

        # Lightsail instances
        if 'lightsail' in config.global_inventory:
            inv_lightsail["lightsail"] = config.global_inventory["lightsail"]

        # autoscaling
        if 'autoscaling' in config.global_inventory:
            inv_autoscaling["autoscaling"] = config.global_inventory["autoscaling"]

        # EKS inventory
        if 'eks' in config.global_inventory:
            inv_eks["eks"] = config.global_inventory["eks"]

        # Batch jobs inventory
        if 'batch' in config.global_inventory:
            inv_batch["batch"] = config.global_inventory["batch"]

        # Storage: EFS Inventory, Glacier Inventory, Storage gateway inventory
        if 'efs' in config.global_inventory:
            inv_efs["efs"] = config.global_inventory["efs"]
        
        if 'glacier' in config.global_inventory:
            inv_glacier["glacier"] = config.global_inventory["glacier"]
        
        if 'storagegateway' in config.global_inventory:
            inv_storagegateway["storagegateway"] = config.global_inventory["storagegateway"]

        # Databases: RDS inventory, dynamodb inventory, neptune inventory, redshift inventory, elasticache Inventory
        if 'rds' in config.global_inventory:
            inv_rds["rds"] = config.global_inventory["rds"]
        
        if 'dynamodb' in config.global_inventory:
            inv_dynamodb["dynamodb"] = config.global_inventory["dynamodb"]
        
        if 'neptune' in config.global_inventory:
            inv_neptune["neptune"] = config.global_inventory["neptune"]
        
        if 'redshift' in config.global_inventory:
            inv_redshift["redshift"] = config.global_inventory["redshift"]
        
        if 'elasticache' in config.global_inventory:
            inv_elastic["elasticache"] = config.global_inventory["elasticache"]
        
        if 's3' in config.global_inventory:
            inv_s3["s3"] = config.global_inventory["s3"]

        # inventory[svc] = config.global_inventory[svc] # uncomment for this general/everything else
        # Security & IAM:
        # KMS Inventory
        # Cloud Directory
        # ACM (Certificates) inventory
        # ACMPCA
        # Secrets Manager
        # Cloud HSM
        # Developer Tools: CodeStar Inventory
        # Integration:
        # Simple Queue Service Inventory
        # Amazon MQ Inventory
        # Simple Notification Serv ice inventory
        # Analytics:
        # ElasticSearch
        # Cloudsearch
        # Data Pipeline
        # Elastic MapReduce
        # Management:
        # CloudFormation
        # CloudTrail
        # CloudWatch
        # API Gateway Inventory
        # Route 53 inventory
        # CloudFront Inventory
        # Load Balancer Inventory
        # Load Balancer v2 Inventory
        # Alexa for Business
        # WorkDocs (not implemented)
        # Workmail (not well tested, some rights issues)
        # Cost Explorer (experimental)
        # International Resources ???
        # S3 quick inventory

execution_time = time.time() - t0
print("\n\nAll inventories are done. Duration: {:2f} seconds\n".format(execution_time))

#
# ----------------- Final inventory
#

tracker = 0
timestr = time.strftime("-%Y-%m-%d")
filenames = ['AWS_inv_ec2'+timestr, 'AWS_ec2_network'+timestr, 'AWS_ec2_ebs'+timestr, 'AWS_ec2_vpcs'+timestr, 'AWS_ec2_security_groups'+timestr,
'AWS_ec2_internet_gateways'+timestr, 'AWS_ec2_nat_gateways'+timestr, 'AWS_ec2_subnets'+timestr, 'AWS_ec2_eips'+timestr, 'AWS_ec2_egpu'+timestr,
'AWS_lambdas'+timestr, 'AWS_elasticbeanstalk'+timestr, 'AWS_ecs'+timestr, 'AWS_lightsail'+timestr, 'AWS_autoscaling'+timestr, 'AWS_eks'+timestr, 'AWS_batch'+timestr,
'AWS_efs'+timestr, 'AWS_glacier'+timestr, 'AWS_storagegateway'+timestr, 'AWS_rds'+timestr, 'AWS_dynamodb'+timestr, 'AWS_neptune'+timestr, 'AWS_redshift'+timestr, 'AWS_elasticache'+timestr,
'AWS_general'+timestr, 'AWS_s3'+timestr]

inv_vars = [inv_ec2, inv_ec2_network_interfaces, inv_ec2_ebs, inv_ec2_vpcs, inv_ec2_security_groups, inv_ec2_internet_gateways,
inv_ec2_nat_gateways, inv_ec2_subnets, inv_ec2_eips, inv_ec2_egpu, inv_lambda, inv_elastic, inv_ecs, inv_lightsail, inv_autoscaling,
inv_eks, inv_batch, inv_efs, inv_glacier, inv_storagegateway, inv_rds, inv_dynamodb, inv_neptune, inv_redshift, inv_elasticache,
inventory, inv_s3]

for name in filenames:
    filename_json = name+".json".format(ownerId, config.timestamp)

    try:
        if inv_vars[tracker]:
            json_file = open(config.filepath+filename_json,'w+')
            json.dump(inv_vars[tracker], json_file, indent=4)
            json_file.close()
    except IOError as e:
        config.logger.error("I/O error({0}): {1}".format(e.errno, e.strerror))
    tracker += 1

#
# ----------------- For Information: list of regions and availability zones
#

filename_regions_json = 'AWS_Regions_List'+timestr+'.json'
try:
    json_file = open(config.filepath+filename_regions_json,'w+')
    json_file.write(json.JSONEncoder().encode(config.regions))
    json_file.close()
except IOError as e:
    config.logger.error("I/O error({0}): {1}".format(e.errno, e.strerror))

#
# EOF
#

#
# This is the end
#
print("End of processing.\n")
