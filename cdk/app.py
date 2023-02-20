#!/usr/bin/env python3
import os
import yaml
import aws_cdk as cdk
from aws_cdk import App, Tags, Environment
import yaml

from stacks.webhook_stack import WebhookStack
from stacks.scanner_stack import ScannerStack
from stacks.build_stack import BuildStack
from pprint import pprint

config=yaml.safe_load(open('config.yaml'))

env_main = cdk.Environment(
    #account=config['env']['id'], 
    account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),    
    region=config['env']['region']
    )
props={}
namespace = 'ironbank-rhel-ubi-python-3-9'

app = cdk.App()

webhook_stack = WebhookStack(
    app, 
    f"{config['app']['namespace']}-webhook",
    upstream_name=f"{config['app']['namespace']}-webhook",
    env=Environment(
        account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
        region="us-east-1"       
    ),    
)

scanner_stack = ScannerStack(
    app, 
    f"{config['app']['namespace']}-scanner",
    env=Environment(
        account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
        region="us-east-1"       
    ),    
)

build_stack = BuildStack(
    app, 
    f"{namespace}",    #Set the stack name.
    namespace,         #This propagates through.
    env=Environment(
        account=os.environ.get("CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"]),
        region="us-east-1"       
    )
)
Tags.of(build_stack).add("ApplicationGroup", "DevOpsAutomation2021")

app.synth()
