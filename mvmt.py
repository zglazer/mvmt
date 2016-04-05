#! /usr/bin/env python

"""The Movement. A Gusto Sites Amazon Web Services Utility for creating and
managing static websites on Amazon S3.

Usage:
    mvmt.py new DOMAIN [--region=REGION]
    mvmt.py push DOMAIN DIRECTORY [--region=REGION]
    mvmt.py clean DOMAIN [--region=REGION]
    mvmt.py del DOMAIN [--region=REGION]
    mvmt.py route DOMAIN [--region=REGION] [--comment=COMMENT]
    mvmt.py -h | --help

Arguments:
    DOMAIN             The root domain of your website. This will also be your
                       bucket name.

    DIRECTORY          The directory that will be pushed to S3.
                       Can be an absolute or relative path.
Options:
    -h --help          Show this screen.
    --region=REGION    Specify an AWS region. [default: us-east-1]
    --comment=COMMENT  Specify a comment for your new hosted zone.
                       [default: My New Website]

"""
# import system libraries
import sys
from string import Template
import logging
import os.path
import mimetypes
import uuid
import re

# set logger
logging.basicConfig()
logger = logging.getLogger('TheMovement')

# import third-party libraries
from docopt import docopt
import boto3
import botocore.exceptions

DEFAULT_BUCKET_POLICY = ('{\n'
                         '  "Version":"2012-10-17",\n'
                         '  "Statement":[{\n'
                         '    "Sid":"AddPerm",\n'
                         '    "Effect":"Allow",\n'
                         '    "Principal": "*",\n'
                         '    "Action":["s3:GetObject"],\n'
                         '    "Resource":["arn:aws:s3:::$domain/*"]\n'
                         '    }]\n'
                         '}')

IGNORE_LIST = ['.DS_Store']
REGION_LIST = ['us-east-1', 'us-west-2', 'us-west-1', 'eu-west-1', 'eu-central-1',
               'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'sa-east-1']
DOMAIN_PATTERN = re.compile(
    r'^(?!\-)(?:[a-zA-Z\d\-]{0,62}[a-zA-Z\d]\.)'
    r'{1,126}(?!\d+)[a-zA-Z\d]{1,63}$'
)


def is_valid_domain(domain):
    """
    Checks for a valid domain name.
    :param domain:
    :return:
    """
    if DOMAIN_PATTERN.match(domain) is None:
        logger.error('The domain provided is not valid.')
        return False
    return True


def is_valid_region(aws_region):
    """
    Checks for a valid AWS S3 region. See REGION_LIST for accepted regions.
    :param aws_region:
    :return:
    """
    if aws_region in REGION_LIST:
        return True
    logger.error(aws_region + ' is not a valid S3 region.')
    logger.info('Supported regions: ' + repr(REGION_LIST))
    return False


def validate_all_arguments(args):
    """
    Argument validation.
    :param args:
    :return:    True if all arguments are valid. False otherwise.
    """
    aws_region = args['--region']
    if not is_valid_region(aws_region):
        return False
    domain = args['DOMAIN']
    if not is_valid_domain(domain):
        return False
    return True


def create_new_website(args):
    """
    Creates a new website on AWS S3 by creating buckets and
    configuring for static site hosting.
    :param args:    command line arguments
    :return:        None
    """
    domain = args['DOMAIN']
    if '.' not in domain:
        print 'Error: invalid domain name. Try DOMAIN.TLD'
        sys.exit()

    # split domain
    domain = domain.split('.')
    domain = [domain[-2], domain[-1]]
    root_domain = '.'.join(domain)
    www_domain = 'www.' + root_domain

    # get region
    aws_region = args['--region']

    # start creating the buckets
    print 'Creating new AWS buckets...'
    print 'Creating ' + root_domain + ', ' + www_domain + '...'
    s3 = boto3.resource('s3', region_name=aws_region)

    # try creating the buckets
    try:
        s3.create_bucket(ACL='public-read', Bucket=root_domain)
        s3.create_bucket(ACL='public-read', Bucket=www_domain)
        print 'Buckets successfully created. Configuring buckets for hosting...'
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        sys.exit()

    # configure bucket policy for static site hosting
    policy = Template(DEFAULT_BUCKET_POLICY).substitute(dict(domain=www_domain))
    try:
        s3.BucketPolicy(www_domain).put(Policy=policy)
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        sys.exit()

    # configure bucket for static site hosting
    try:
        s3.BucketWebsite(www_domain).put(
                WebsiteConfiguration={
                    'ErrorDocument': {
                        'Key': '404.html'
                    },
                    'IndexDocument': {
                        'Suffix': 'index.html'
                    }
                }
        )
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        sys.exit()

    # redirect requests to www subdomain from root domain
    try:
        s3.BucketWebsite(root_domain).put(
                WebsiteConfiguration={
                    'RedirectAllRequestsTo': {
                        'HostName': www_domain
                    }
                }
        )
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        sys.exit()

    # all finished
    print 'All finished. Buckets are ready for code.'


def push_code(args):
    """
    Push directory contents to AWS S3 bucket.
    :param args:    command line arguments
    :return:        None
    """
    domain = args['DOMAIN']
    domain = "www." + domain
    directory = args['DIRECTORY']

    if not os.path.isdir(directory):
        logger.error(directory + ' is not a valid directory.')
        sys.exit()

    # get region
    aws_region = arguments['--region']

    # connect to s3 bucket
    s3 = boto3.resource('s3', region_name=aws_region)
    s3_bucket = s3.Bucket(domain)

    # check if bucket exists
    if s3_bucket not in s3.buckets.all():
        logging.error(domain + ' does not exist or you do not have access.')
        sys.exit()

    # upload all files in directory recursively
    logger.info('Pushing directory to S3...')
    for root, dirs, files in os.walk(directory):
        rel_path = os.path.relpath(root, directory)
        for filename in files:
            # ignore certain files
            if filename in IGNORE_LIST:
                continue
            # there is no concept of directories in s3
            # we use relative path as part of the key
            if rel_path is '.':
                s3_key = filename
            else:
                s3_key = os.path.join(rel_path, filename)
            # open file and put on s3
            full_path = os.path.join(root, filename)
            mimetype = mimetypes.guess_type(full_path)[0]
            if mimetype is None:
                mimetype = ''
            logger.info('Pushing ' +
                        filename + ' [Content-Type=' + mimetype + ']...')
            with open(full_path, 'rb') as f:
                s3_bucket.put_object(Key=s3_key, Body=f, ContentType=mimetype)
    logger.info('Success. Code has been pushed.')
    s3_website = domain + '.s3-website-' + aws_region + '.amazonaws.com'
    logger.info('Check out your website: ' + s3_website)


def clean_site(args):
    """
    Deletes all contents of a bucket.
    :param args:    command line arguments
    :return:        None
    """
    domain = args['DOMAIN']
    domain = "www." + domain

    # get region
    aws_region = arguments['--region']

    # connect to s3 bucket
    s3 = boto3.resource('s3', region_name=aws_region)
    s3_bucket = s3.Bucket(domain)

    # iterate through the bucket and delete the objects
    for obj in s3_bucket.objects.all():
        obj.delete()

    logger.info('Contents of ' + s3_bucket.name + ' have been deleted.')


def configure_dns(args):
    """
    Create Route53 hosted zone and configure record set.
    :param args:    command line arguments
    :return:        None
    """
    domain = args['DOMAIN']
    aws_region = args['--region']
    hosted_zone_comment = args['--comment']

    www_domain = 'www.' + domain
    s3_website = www_domain + '.s3-website-' + aws_region + '.amazonaws.com'

    # create Route53 client
    client = boto3.client('route53')

    # create the new hosted zone
    logger.info('Creating new Route53 hosted zone...')
    hosted_zone_config = {'Comment': hosted_zone_comment,
                           'PrivateZone': False}
    try:
        hosted_zone = client.create_hosted_zone(
            Name=domain,
            CallerReference='TheMovement_' + uuid.uuid4(),
            HostedZoneConfig=hosted_zone_config
        )
    except botocore.exceptions.ClientError as e:
        logger.error(e)
        sys.exit()

    hosted_zone_id = hosted_zone['HostedZone']['Id']
    change_batch = {
        'Changes':
            [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet':
                        {
                            'Name': www_domain,
                            'Type': 'A',
                            'AliasTarget':
                                {
                                    'HostedZoneId': hosted_zone_id,
                                    'DNSName': s3_website,
                                    'EvaluateTargetHealth': False
                                }
                        }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet':
                        {
                            'Name': domain,
                            'Type': 'A',
                            'AliasTarget':
                                {
                                    'HostedZoneId': hosted_zone_id,
                                    'DNSName': www_domain,
                                    'EvaluateTargetHealth': False
                                }
                        }
                }
            ]
    }

    response = client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch=change_batch
    )

    logger.info('Route53 requests sent. Status is currently: ' + response['Status'])

    # user needs NS record list to update current DNS
    ns_list = hosted_zone['DelegationSet']['NameServers']

    logger.info('Configuration complete. '
                'Please go to your registrar and update your '
                'NS records to the following:')
    logger.info(ns_list)


if __name__ == '__main__':
    logger.setLevel(logging.INFO)

    arguments = docopt(__doc__)
    logger.debug(arguments)

    if not validate_all_arguments(arguments):
        logger.error('Error in validating arguments. Quitting...')
        sys.exit()

    # start running commands

    # create a new S3 bucket with static site configurations
    if arguments['new']:
        create_new_website(arguments)

    if arguments['clean']:
        clean_site(arguments)

    # push directory contents to AWS S3 bucket
    if arguments['push']:
        push_code(arguments)

    # configure DNS using Route53
    if arguments['route']:
        configure_dns(arguments)
