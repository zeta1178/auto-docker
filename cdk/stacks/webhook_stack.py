from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    aws_iam as iam,
    aws_sqs as sqs,
    aws_sns as sns,
    aws_ssm,
    aws_s3,
    aws_ec2,
    aws_iam,
    aws_lambda,
    aws_codecommit,
    aws_apigateway,
    aws_kms,
    aws_secretsmanager,
    aws_sns_subscriptions as subs,
    RemovalPolicy, Aws, CfnOutput
)

class WebhookStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, upstream_name, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        def security_group(id):
            return aws_ec2.SecurityGroup.from_security_group_id(self, id, id)     

        # get env variables
        accountid = Stack.of(self).account

        region = Stack.of(self).region   
        #Setup of variables. Lambda runs in a VPC, no egress traffic.
        subnet_id_1   = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/subnet1")
        subnet_id_2   = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/subnet2")
        vpc_id        = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/vpc")
        sg_id_1       = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/lambda/security-group-id")
        bitbucket_uri = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/devsecops/bitbucket/uri")            
        
        vpc = aws_ec2.Vpc.from_lookup(self, 'vpc',
          vpc_id = vpc_id,
        )

        subnet_1         = aws_ec2.Subnet.from_subnet_id(self, "subnet1", subnet_id_1)        
        subnet_2         = aws_ec2.Subnet.from_subnet_id(self, "subnet2", subnet_id_2)
        security_group_1 = aws_ec2.SecurityGroup.from_security_group_id(self, "Lambda Security Group", sg_id_1)
        vpc_subnets      = aws_ec2.SubnetSelection(subnets=[subnet_1, subnet_2])            

        lambda_bitbucket_webhook_role = aws_iam.Role(self, "lambda_parser_role",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com")
        )                 
        lambda_bitbucket_webhook_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))
        lambda_bitbucket_webhook_role.add_managed_policy(aws_iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole"))
        
        pat_secret = aws_secretsmanager.Secret.from_secret_name_v2(self, "BitbucketSecrets", "/amtrak/devsecops/bitbucket/pat")    
        # locates the ssm parameter for the bitbucket uri
        bitbucket_uri = aws_ssm.StringParameter.value_from_lookup(
            self, "/amtrak/cloud-solutions/devsecops/bitbucket/uri")  
        # Creates bucket for upload
        artifact_bucket = aws_s3.Bucket(
            self, 
            f"{upstream_name}-Artifacts",
            bucket_name=f"{Stack.of(self).stack_name}-artifacts",
            versioned=True,
            enforce_ssl=True,
            object_ownership=aws_s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            block_public_access=aws_s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY
        )        

        crypto_layer = aws_lambda.LayerVersion(self, "CryptoLayer",
            removal_policy=RemovalPolicy.DESTROY,
            code = aws_lambda.AssetCode('lambda/layer/crypto'),
            compatible_runtimes = [aws_lambda.Runtime.PYTHON_3_9],
        )

        requests_layer = aws_lambda.LayerVersion(self, "RequestsLayer",
            removal_policy=RemovalPolicy.DESTROY,
            code = aws_lambda.AssetCode('lambda/layer/requests'),
            compatible_runtimes = [aws_lambda.Runtime.PYTHON_3_9],
        )

        bitbucket_webhook_function = aws_lambda.Function(self, 'BitbucketWebhookFunction',
          code=aws_lambda.AssetCode('lambda/webhook'),
          runtime=aws_lambda.Runtime.PYTHON_3_9,
          timeout=Duration.seconds(300),
          memory_size=3008,
          layers=[crypto_layer,requests_layer],
          handler='lambda_function.lambda_handler',
          role=lambda_bitbucket_webhook_role,
          tracing = aws_lambda.Tracing.ACTIVE,
          insights_version=aws_lambda.LambdaInsightsVersion.VERSION_1_0_98_0,
          vpc = vpc,
          vpc_subnets=vpc_subnets,           
          security_groups=[security_group_1],          
          environment={
              "BITBUCKET_TOKEN" :  pat_secret.secret_arn,
              "BITBUCKET_SECRET" : pat_secret.secret_arn,
              "BITBUCKET_SERVER_URI" : bitbucket_uri,
              "S3BUCKET" : artifact_bucket.bucket_name,
          }
        )
        
        pat_secret.grant_read(bitbucket_webhook_function)
        artifact_bucket.grant_read_write(bitbucket_webhook_function)
        #This API should be run from the VPC, but disabling temporarily until
        #VPC endpoints are working with the Bitbucket server. May be replaced
        #by Bitbucket Cloud. 
        #vpc.add_interface_endpoint("PrivateAPIEndpoint",
        #    service=aws_ec2.InterfaceVpcEndpointAwsService.APIGATEWAY
        #)       
        '''
        vpc_endpoint = aws_ec2.InterfaceVpcEndpoint(self, 
            id="vpcendpoint", 
            vpc=vpc, 
            service=aws_ec2.InterfaceVpcEndpointAwsService.APIGATEWAY,
            #subnets=aws_ec2.SubnetSelection(subnets=subnet_list)
        )   
        '''
        #source_ip_list = ['10.0.0.0/16']

        #private_api_policy = aws_iam.PolicyStatement()
        api_resource_policy = iam.PolicyDocument()
        api_resource_policy.add_statements(iam.PolicyStatement(
            actions=["execute-api:Invoke"],
            resources=["execute-api:/*"],                              
            principals=[aws_iam.AnyPrincipal()],
            )
        )   

        api = aws_apigateway.RestApi(self, "bitbucket_webhook_api",
            rest_api_name="Bitbucket Webhook API",
            description="This syncs BitBucket Server to CodeCommit.",
            deploy_options=aws_apigateway.StageOptions(
                logging_level=aws_apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
            )
        )

        get_widgets_integration = aws_apigateway.LambdaIntegration(bitbucket_webhook_function,
            request_templates={"application/json": '{ "statusCode": "200" }'}
        )

        api_method="POST"
        api.root.add_method(f"{api_method}", get_widgets_integration)

        #creates resource based policy for API endpoint to invoke lambda function
        bitbucket_webhook_function.add_permission(
            "lambdaResourceBasedPolicy",
            action= "lambda:InvokeFunction",
            principal=iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_account=f"{Aws.ACCOUNT_ID}",
            source_arn=f"arn:aws:execute-api:{Aws.REGION}:{Aws.ACCOUNT_ID}:{api.rest_api_id}/*/{api_method}/"
        )

        artifact_key = aws_kms.Key(self, "ArtifactKey",
            enable_key_rotation=True,
            #alias='ArtifactKey',
            alias=f"{Stack.of(self).stack_name}-webhook-key",            
        )
        artifact_key_alias = aws_kms.Alias(self, "ReplicationAlias",
            #alias_name="S3KMSKey",
            alias_name=f"{Stack.of(self).stack_name}-webhook-key-alias",
            target_key=artifact_key
        )   
        artifact_key.grant_decrypt(lambda_bitbucket_webhook_role)    

        aws_ssm.StringParameter(self, "ArtifactBucket",
            description="This bucket is used to store container images.",
            parameter_name="/amtrak/devsecops/container-build-pipeline/artifact-bucket",
            string_value=artifact_bucket.bucket_arn,
        )            

        self.artifact_bucket=artifact_bucket

    #Export objects.
    @property
    def outputs(self):
        return self        