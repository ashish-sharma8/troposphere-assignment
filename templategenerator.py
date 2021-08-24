import troposphere.ec2 as ec2
from troposphere import Base64, Join, ImportValue
from troposphere import AWSObject, AWSProperty, Tags
from troposphere.cloudwatch import Alarm, MetricDimension
from troposphere import GetAtt, Output, Parameter, Ref, Template
import troposphere.elasticloadbalancingv2 as elb
from troposphere import (
    Base64,
    FindInMap,
    GetAtt,
    Join,
    Output,
    Parameter,
    Tags,
    Ref,
    Template,
)

from troposphere.autoscaling import Metadata
from troposphere.cloudformation import (
    Init,
    InitConfig,
    InitFile,
    InitFiles,
    InitService,
    InitServices,
)
from troposphere.ec2 import (
    EIP,
    VPC,
    Instance,
    InternetGateway,
    NetworkAcl,
    NetworkAclEntry,
    NetworkInterfaceProperty,
    PortRange,
    Route,
    RouteTable,
    SecurityGroup,
    SecurityGroupRule,
    Subnet,
    SubnetNetworkAclAssociation,
    SubnetRouteTableAssociation,
    VPCGatewayAttachment,
)

from troposphere.policies import CreationPolicy, ResourceSignal
t = Template()

t.set_version("2010-09-09")

t.set_description(
    """\
AWS CloudFormation Sample Template VPC_Single_Instance_In_Subnet: Sample \
t showing how to create a VPC and add an EC2 instance with an Elastic \
IP address and a security group. \
**WARNING** This t creates an Amazon EC2 instance. You will be billed \
for the AWS resources used if you create a stack from this t."""
)

keyname_param = t.add_parameter(
    Parameter(
        "KeyName",
        ConstraintDescription="must be the name of an existing EC2 KeyPair.",
        Description="Name of an existing EC2 KeyPair to enable SSH access to \
the instance",
        Type="AWS::EC2::KeyPair::KeyName",
    )
)

sshlocation_param = t.add_parameter(
    Parameter(
        "SSHLocation",
        Description=" The IP address range that can be used to SSH to the EC2 \
instances",
        Type="String",
        MinLength="9",
        MaxLength="18",
        Default="0.0.0.0/0",
        AllowedPattern=r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})",
        ConstraintDescription=("must be a valid IP CIDR range of the form x.x.x.x/x."),
    )
)

instanceType_param = t.add_parameter(
    Parameter(
        "InstanceType",
        Type="String",
        Description="WebServer EC2 instance type",
        Default="t2.micro",
        AllowedValues=[
            "t1.micro",
            "t2.micro",
            "t2.small",
            "t2.medium",
            "m1.small",
            "m1.medium",
            "m1.large",
            "m1.xlarge",
            "m2.xlarge",
            "m2.2xlarge",
            "m2.4xlarge",
            "m3.medium",
            "m3.large",
            "m3.xlarge",
            "m3.2xlarge",
            "c1.medium",
            "c1.xlarge",
            "c3.large",
            "c3.xlarge",
            "c3.2xlarge",
            "c3.4xlarge",
            "c3.8xlarge",
            "g2.2xlarge",
            "r3.large",
            "r3.xlarge",
            "r3.2xlarge",
            "r3.4xlarge",
            "r3.8xlarge",
            "i2.xlarge",
            "i2.2xlarge",
            "i2.4xlarge",
            "i2.8xlarge",
            "hi1.4xlarge",
            "hs1.8xlarge",
            "cr1.8xlarge",
            "cc2.8xlarge",
            "cg1.4xlarge",
        ],
        ConstraintDescription="must be a valid EC2 instance type.",
    )
)

t.add_mapping(
    "AWSInstanceType2Arch",
    {
        "t1.micro": {"Arch": "PV64"},
        "t2.micro": {"Arch": "HVM64"},
        "t2.small": {"Arch": "HVM64"},
        "t2.medium": {"Arch": "HVM64"},
        "m1.small": {"Arch": "PV64"},
        "m1.medium": {"Arch": "PV64"},
        "m1.large": {"Arch": "PV64"},
        "m1.xlarge": {"Arch": "PV64"},
        "m2.xlarge": {"Arch": "PV64"},
        "m2.2xlarge": {"Arch": "PV64"},
        "m2.4xlarge": {"Arch": "PV64"},
        "m3.medium": {"Arch": "HVM64"},
        "m3.large": {"Arch": "HVM64"},
        "m3.xlarge": {"Arch": "HVM64"},
        "m3.2xlarge": {"Arch": "HVM64"},
        "c1.medium": {"Arch": "PV64"},
        "c1.xlarge": {"Arch": "PV64"},
        "c3.large": {"Arch": "HVM64"},
        "c3.xlarge": {"Arch": "HVM64"},
        "c3.2xlarge": {"Arch": "HVM64"},
        "c3.4xlarge": {"Arch": "HVM64"},
        "c3.8xlarge": {"Arch": "HVM64"},
        "g2.2xlarge": {"Arch": "HVMG2"},
        "r3.large": {"Arch": "HVM64"},
        "r3.xlarge": {"Arch": "HVM64"},
        "r3.2xlarge": {"Arch": "HVM64"},
        "r3.4xlarge": {"Arch": "HVM64"},
        "r3.8xlarge": {"Arch": "HVM64"},
        "i2.xlarge": {"Arch": "HVM64"},
        "i2.2xlarge": {"Arch": "HVM64"},
        "i2.4xlarge": {"Arch": "HVM64"},
        "i2.8xlarge": {"Arch": "HVM64"},
        "hi1.4xlarge": {"Arch": "HVM64"},
        "hs1.8xlarge": {"Arch": "HVM64"},
        "cr1.8xlarge": {"Arch": "HVM64"},
        "cc2.8xlarge": {"Arch": "HVM64"},
    },
)

t.add_mapping(
    "AWSRegionArch2AMI",
    {
        "us-east-1": {
            "PV64": "ami-50842d38",
            "HVM64": "ami-08842d60",
            "HVMG2": "ami-3a329952",
        },
        "us-west-2": {
            "PV64": "ami-af86c69f",
            "HVM64": "ami-8786c6b7",
            "HVMG2": "ami-47296a77",
        },
        "us-west-1": {
            "PV64": "ami-c7a8a182",
            "HVM64": "ami-cfa8a18a",
            "HVMG2": "ami-331b1376",
        },
        "eu-west-1": {
            "PV64": "ami-aa8f28dd",
            "HVM64": "ami-748e2903",
            "HVMG2": "ami-00913777",
        },
        "ap-southeast-1": {
            "PV64": "ami-20e1c572",
            "HVM64": "ami-d6e1c584",
            "HVMG2": "ami-fabe9aa8",
        },
        "ap-northeast-1": {
            "PV64": "ami-21072820",
            "HVM64": "ami-35072834",
            "HVMG2": "ami-5dd1ff5c",
        },
        "ap-southeast-2": {
            "PV64": "ami-8b4724b1",
            "HVM64": "ami-fd4724c7",
            "HVMG2": "ami-e98ae9d3",
        },
        "sa-east-1": {
            "PV64": "ami-9d6cc680",
            "HVM64": "ami-956cc688",
            "HVMG2": "NOT_SUPPORTED",
        },
        "cn-north-1": {
            "PV64": "ami-a857c591",
            "HVM64": "ami-ac57c595",
            "HVMG2": "NOT_SUPPORTED",
        },
        "eu-central-1": {
            "PV64": "ami-a03503bd",
            "HVM64": "ami-b43503a9",
            "HVMG2": "ami-b03503ad",
        },
    },
)

ref_stack_id = Ref("AWS::StackId")
ref_region = Ref("AWS::Region")
ref_stack_name = Ref("AWS::StackName")

VPC = t.add_resource(
    VPC("VPC", CidrBlock="10.0.0.0/16", Tags=Tags(Application=ref_stack_id))
)

subnet = t.add_resource(
    Subnet(
        "Subnet",
        CidrBlock="10.0.0.0/24",
        VpcId=Ref(VPC),
        Tags=Tags(Application=ref_stack_id),
    )
)

internetGateway = t.add_resource(
    InternetGateway("InternetGateway", Tags=Tags(Application=ref_stack_id))
)

gatewayAttachment = t.add_resource(
    VPCGatewayAttachment(
        "AttachGateway", VpcId=Ref(VPC), InternetGatewayId=Ref(internetGateway)
    )
)

routeTable = t.add_resource(
    RouteTable("RouteTable", VpcId=Ref(VPC), Tags=Tags(Application=ref_stack_id))
)

route = t.add_resource(
    Route(
        "Route",
        DependsOn="AttachGateway",
        GatewayId=Ref("InternetGateway"),
        DestinationCidrBlock="0.0.0.0/0",
        RouteTableId=Ref(routeTable),
    )
)

subnetRouteTableAssociation = t.add_resource(
    SubnetRouteTableAssociation(
        "SubnetRouteTableAssociation",
        SubnetId=Ref(subnet),
        RouteTableId=Ref(routeTable),
    )
)

networkAcl = t.add_resource(
    NetworkAcl(
        "NetworkAcl",
        VpcId=Ref(VPC),
        Tags=Tags(Application=ref_stack_id),
    )
)

inBoundPrivateNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundHTTPNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="100",
        Protocol="6",
        PortRange=PortRange(To="80", From="80"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

inboundSSHNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundSSHNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="101",
        Protocol="6",
        PortRange=PortRange(To="22", From="22"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

inboundResponsePortsNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "InboundResponsePortsNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="102",
        Protocol="6",
        PortRange=PortRange(To="65535", From="1024"),
        Egress="false",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundHTTPNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundHTTPNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="100",
        Protocol="6",
        PortRange=PortRange(To="80", From="80"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundHTTPSNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundHTTPSNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="101",
        Protocol="6",
        PortRange=PortRange(To="443", From="443"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

outBoundResponsePortsNetworkAclEntry = t.add_resource(
    NetworkAclEntry(
        "OutBoundResponsePortsNetworkAclEntry",
        NetworkAclId=Ref(networkAcl),
        RuleNumber="102",
        Protocol="6",
        PortRange=PortRange(To="65535", From="1024"),
        Egress="true",
        RuleAction="allow",
        CidrBlock="0.0.0.0/0",
    )
)

subnetNetworkAclAssociation = t.add_resource(
    SubnetNetworkAclAssociation(
        "SubnetNetworkAclAssociation",
        SubnetId=Ref(subnet),
        NetworkAclId=Ref(networkAcl),
    )
)

instanceSecurityGroup = t.add_resource(
    SecurityGroup(
        "InstanceSecurityGroup",
        GroupDescription="Enable SSH access via port 22",
        SecurityGroupIngress=[
            SecurityGroupRule(
                IpProtocol="tcp",
                FromPort="22",
                ToPort="22",
                CidrIp=Ref(sshlocation_param),
            ),
            SecurityGroupRule(
                IpProtocol="tcp", FromPort="80", ToPort="80", CidrIp="0.0.0.0/0"
            ),
        ],
        VpcId=Ref(VPC),
    )
)

instance_metadata = Metadata(
    Init(
        {
            "config": InitConfig(
                packages={"yum": {"nginx": []}},
                files=InitFiles(
                    {
                        "/var/www/html/index.html": InitFile(
                            content=Join(
                                "\n",
                                [
                                    '<img \
src="https://s3.amazonaws.com/cloudformation-examples/\
cloudformation_graphic.png" alt="AWS CloudFormation Logo"/>',
                                    "<h1>\
Congratulations, you have successfully launched the AWS CloudFormation sample.\
</h1>",
                                ],
                            ),
                            mode="000644",
                            owner="root",
                            group="root",
                        ),

                        "/etc/cfn/cfn-hup.conf": InitFile(
                            content=Join(
                                "",
                                [
                                    "[main]\n",
                                    "stack=",
                                    ref_stack_id,
                                    "\n",
                                    "region=",
                                    ref_region,
                                    "\n",
                                ],
                            ),
                            mode="000400",
                            owner="root",
                            group="root",
                        ),
                        "/etc/cfn/hooks.d/cfn-auto-reloader.conf": InitFile(
                            content=Join(
                                "",
                                [
                                    "[cfn-auto-reloader-hook]\n",
                                    "triggers=post.update\n",
                                    "path=Resources.WebServerInstance.\
Metadata.AWS::CloudFormation::Init\n",
                                    "action=/opt/aws/bin/cfn-init -v ",
                                    "         --stack ",
                                    ref_stack_name,
                                    "         --resource WebServerInstance ",
                                    "         --region ",
                                    ref_region,
                                    "\n",
                                    "runas=root\n",
                                ],
                            )
                        ),
                    }
                ),
                services={
                    "sysvinit": InitServices(
                        {
                            "nginx": InitService(enabled=True, ensureRunning=True),
                            "cfn-hup": InitService(
                                enabled=True,
                                ensureRunning=True,
                                files=[
                                    "/etc/cfn/cfn-hup.conf",
                                    "/etc/cfn/hooks.d/cfn-auto-reloader.conf",
                                ],
                            ),
                        }
                    )
                },
            )
        }
    )
)

instance = t.add_resource(
    Instance(
        "WebServerInstance",
        Metadata=instance_metadata,
        ImageId=FindInMap(
            "AWSRegionArch2AMI",
            Ref("AWS::Region"),
            FindInMap("AWSInstanceType2Arch", Ref(instanceType_param), "Arch"),
        ),
        InstanceType=Ref(instanceType_param),
        KeyName=Ref(keyname_param),
        NetworkInterfaces=[
            NetworkInterfaceProperty(
                GroupSet=[Ref(instanceSecurityGroup)],
                AssociatePublicIpAddress="true",
                DeviceIndex="0",
                DeleteOnTermination="true",
                SubnetId=Ref(subnet),
            )
        ],
        UserData=Base64(
            Join(
                "",
                [
                    "#!/bin/bash -xe\n",
                    "yum update -y aws-cfn-bootstrap\n",
                    "sudo yum install nginx -y",
                    "/opt/aws/bin/cfn-init -v ",
                    "         --stack ",
                    Ref("AWS::StackName"),
                    "         --resource WebServerInstance ",
                    "         --region ",
                    Ref("AWS::Region"),
                    "\n",
                    "/opt/aws/bin/cfn-signal -e $? ",
                    "         --stack ",
                    Ref("AWS::StackName"),
                    "         --resource WebServerInstance ",
                    "         --region ",
                    Ref("AWS::Region"),
                    "\n",
                ],
            )
        ),
        CreationPolicy=CreationPolicy(ResourceSignal=ResourceSignal(Timeout="PT15M")),
        Tags=Tags(Application=ref_stack_id),
    )
)

ipAddress = t.add_resource(
    EIP("IPAddress", DependsOn="AttachGateway", Domain="vpc", InstanceId=Ref(instance))
)

t.add_output(
    [
        Output(
            "URL",
            Description="Newly created application URL",
            Value=Join("", ["http://", GetAtt("WebServerInstance", "PublicIp")]),
        )
    ]
)

print(t.to_json())


#if __name__ == "__main__":
#    main()


def AddAMI(template):
    template.add_mapping(
        "RegionMap",
        {
            "us-east-1": {"AMI": "ami-6411e20d"},
            "us-west-1": {"AMI": "ami-c9c7978c"},
            "us-west-2": {"AMI": "ami-fcff72cc"},
            "eu-west-1": {"AMI": "ami-37c2f643"},
            "ap-southeast-1": {"AMI": "ami-66f28c34"},
            "ap-northeast-1": {"AMI": "ami-9c03a89d"},
            "sa-east-1": {"AMI": "ami-a039e6bd"},
        },
    )


def main():
    template = Template()
    template.set_version("2010-09-09")

    template.set_description(
        "AWS CloudFormation Sample Template: ELB with 2 EC2 instances"
    )

    AddAMI(template)

    # Add the Parameters
    keyname_param = template.add_parameter(
        Parameter(
            "KeyName",
            Type="String",
            Default="mark",
            Description="Name of an existing EC2 KeyPair to "
            "enable SSH access to the instance",
        )
    )

    template.add_parameter(
        Parameter(
            "InstanceType",
            Type="String",
            Description="WebServer EC2 instance type",
            Default="m1.small",
            AllowedValues=[
                "t1.micro",
                "m1.small",
                "m1.medium",
                "m1.large",
                "m1.xlarge",
                "m2.xlarge",
                "m2.2xlarge",
                "m2.4xlarge",
                "c1.medium",
                "c1.xlarge",
                "cc1.4xlarge",
                "cc2.8xlarge",
                "cg1.4xlarge",
            ],
            ConstraintDescription="must be a valid EC2 instance type.",
        )
    )

    webport_param = template.add_parameter(
        Parameter(
            "WebServerPort",
            Type="String",
            Default="8888",
            Description="TCP/IP port of the web server",
        )
    )

    apiport_param = template.add_parameter(
        Parameter(
            "ApiServerPort",
            Type="String",
            Default="8889",
            Description="TCP/IP port of the api server",
        )
    )

    subnetA = template.add_parameter(
        Parameter("subnetA", Type="String", Default="subnet-096fd06d")
    )

    subnetB = template.add_parameter(
        Parameter("subnetB", Type="String", Default="subnet-1313ef4b")
    )

    VpcId = template.add_parameter(
        Parameter("VpcId", Type="String", Default="vpc-82c514e6")
    )

    # Define the instance security group
    instance_sg = template.add_resource(
        ec2.SecurityGroup(
            "InstanceSecurityGroup",
            GroupDescription="Enable SSH and HTTP access on the inbound port",
            SecurityGroupIngress=[
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="22",
                    ToPort="22",
                    CidrIp="0.0.0.0/0",
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort=Ref(webport_param),
                    ToPort=Ref(webport_param),
                    CidrIp="0.0.0.0/0",
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort=Ref(apiport_param),
                    ToPort=Ref(apiport_param),
                    CidrIp="0.0.0.0/0",
                ),
            ],
        )
    )

    # Add the web server instance
    WebInstance = template.add_resource(
        ec2.Instance(
            "WebInstance",
            SecurityGroups=[Ref(instance_sg)],
            KeyName=Ref(keyname_param),
            InstanceType=Ref("InstanceType"),
            ImageId=FindInMap("RegionMap", Ref("AWS::Region"), "AMI"),
            UserData=Base64(Ref(webport_param)),
        )
    )

    # Add the api server instance
    ApiInstance = template.add_resource(
        ec2.Instance(
            "ApiInstance",
            SecurityGroups=[Ref(instance_sg)],
            KeyName=Ref(keyname_param),
            InstanceType=Ref("InstanceType"),
            ImageId=FindInMap("RegionMap", Ref("AWS::Region"), "AMI"),
            UserData=Base64(Ref(apiport_param)),
        )
    )

    # Add the application ELB
    ApplicationElasticLB = template.add_resource(
        elb.LoadBalancer(
            "ApplicationElasticLB",
            Name="ApplicationElasticLB",
            Scheme="internet-facing",
            Subnets=[Ref(subnetA), Ref(subnetB)],
        )
    )

    TargetGroupWeb = template.add_resource(
        elb.TargetGroup(
            "TargetGroupWeb",
            HealthCheckIntervalSeconds="30",
            HealthCheckProtocol="HTTP",
            HealthCheckTimeoutSeconds="10",
            HealthyThresholdCount="4",
            Matcher=elb.Matcher(HttpCode="200"),
            Name="WebTarget",
            Port=Ref(webport_param),
            Protocol="HTTP",
            Targets=[
                elb.TargetDescription(Id=Ref(WebInstance), Port=Ref(webport_param))
            ],
            UnhealthyThresholdCount="3",
            VpcId=Ref(VpcId),
        )
    )

    TargetGroupApi = template.add_resource(
        elb.TargetGroup(
            "TargetGroupApi",
            HealthCheckIntervalSeconds="30",
            HealthCheckProtocol="HTTP",
            HealthCheckTimeoutSeconds="10",
            HealthyThresholdCount="4",
            Matcher=elb.Matcher(HttpCode="200"),
            Name="ApiTarget",
            Port=Ref(apiport_param),
            Protocol="HTTP",
            Targets=[
                elb.TargetDescription(Id=Ref(ApiInstance), Port=Ref(apiport_param))
            ],
            UnhealthyThresholdCount="3",
            VpcId=Ref(VpcId),
        )
    )

    Listener = template.add_resource(
        elb.Listener(
            "Listener",
            Port="80",
            Protocol="HTTP",
            LoadBalancerArn=Ref(ApplicationElasticLB),
            DefaultActions=[
                elb.Action(Type="forward", TargetGroupArn=Ref(TargetGroupWeb))
            ],
        )
    )

    template.add_resource(
        elb.ListenerRule(
            "ListenerRuleApi",
            ListenerArn=Ref(Listener),
            Conditions=[elb.Condition(Field="path-pattern", Values=["/api/*"])],
            Actions=[elb.Action(Type="forward", TargetGroupArn=Ref(TargetGroupApi))],
            Priority="1",
        )
    )

    template.add_output(
        Output(
            "URL",
            Description="URL of the sample website",
            Value=Join("", ["http://", GetAtt(ApplicationElasticLB, "DNSName")]),
        )
    )

    print(template.to_json())


if __name__ == "__main__":
    main()

from troposphere import GetAtt, Output, Parameter, Ref, Template
from troposphere.cloudwatch import Alarm, MetricDimension
from troposphere.sns import Subscription, Topic
from troposphere.sqs import Queue

t = Template()

t.set_description(
    "AWS CloudFormation Sample Template with CloudWatch Alarm."
)

alarmemail = t.add_parameter(
    Parameter(
        "AlarmEmail",
        Default="nobody@amazon.com",
        Description="Email address to notify if there are any " "operational issues",
        Type="String",
    )
)

alarmtopic = t.add_resource(
    Topic(
        "AlarmTopic",
        Subscription=[
            Subscription(Endpoint=Ref(alarmemail), Protocol="email"),
        ],
    )
)

ec2alarm = t.add_resource(
    Alarm(
        "ec2Alarm",
        AlarmDescription="Alarm if cpu > 50%",
        Namespace="AWS/EC2",
        MetricName="EC2 THRESHOLD",
        Statistic="Average",
        Period="300",
        EvaluationPeriods="1",
        Threshold="50",
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=[
            Ref(alarmtopic),
        ],
        InsufficientDataActions=[
            Ref(alarmtopic),
        ],
    )
)

print(t.to_json())

import troposphere.ec2 as ec2
import troposphere.elasticloadbalancing as elb
from troposphere import (
    Base64,
    Join,
    Parameter,
    Ref,
    Template,
    autoscaling,
    cloudformation,
)
from troposphere.autoscaling import AutoScalingGroup, LaunchConfiguration, Tag
from troposphere.elasticloadbalancing import LoadBalancer
from troposphere.policies import (
    AutoScalingReplacingUpdate,
    AutoScalingRollingUpdate,
    UpdatePolicy,
)

t = Template()

t.set_description(
    """\
Configures autoscaling group"""
)

SecurityGroup = t.add_parameter(
    Parameter(
        "SecurityGroup",
        Type="String",
        Description="Security group for instances.",
    )
)

DeployBucket = t.add_parameter(
    Parameter(
        "DeployBucket",
        Type="String",
        Description="The S3 bucket with the cloudformation scripts.",
    )
)

SSLCertificateId = t.add_parameter(
    Parameter(
        "SSLCertificateId",
        Type="String",
        Description="SSL certificate for load balancer.",
    )
)

DeployUserAccessKey = t.add_parameter(
    Parameter(
        "DeployUserAccessKey",
        Type="String",
        Description="The access key of the deploy user",
    )
)

KeyName = t.add_parameter(
    Parameter(
        "KeyName",
        Type="String",
        Description="Name of an existing EC2 KeyPair to enable SSH access",
        MinLength="1",
        AllowedPattern="[\x20-\x7E]*",
        MaxLength="255",
        ConstraintDescription="can contain only ASCII characters.",
    )
)

DeployUserSecretKey = t.add_parameter(
    Parameter(
        "DeployUserSecretKey",
        Type="String",
        Description="The secret key of the deploy user",
    )
)

LoadBalancerSecurityGroup = t.add_parameter(
    Parameter(
        "LoadBalancerSecurityGroup",
        Type="String",
        Description="Security group for api app load balancer.",
    )
)

ScaleCapacity = t.add_parameter(
    Parameter(
        "ScaleCapacity",
        Default="1",
        Type="String",
        Description="Number of api servers to run",
    )
)

AmiId = t.add_parameter(
    Parameter(
        "AmiId",
        Type="String",
        Description="The AMI id for the api instances",
    )
)

EnvType = t.add_parameter(
    Parameter(
        "EnvType",
        Type="String",
        Description="The environment being deployed into",
    )
)

PublicSubnet1 = t.add_parameter(
    Parameter(
        "PublicSubnet1",
        Type="String",
        Description="A public VPC subnet ID for the api app load balancer.",
    )
)

PublicSubnet2 = t.add_parameter(
    Parameter(
        "PublicSubnet2",
        Type="String",
        Description="A public VPC subnet ID for the api load balancer.",
    )
)

VPCAvailabilityZone2 = t.add_parameter(
    Parameter(
        "VPCAvailabilityZone2",
        MinLength="1",
        Type="String",
        Description="Second availability zone",
        MaxLength="255",
    )
)

VPCAvailabilityZone1 = t.add_parameter(
    Parameter(
        "VPCAvailabilityZone1",
        MinLength="1",
        Type="String",
        Description="First availability zone",
        MaxLength="255",
    )
)

RootStackName = t.add_parameter(
    Parameter(
        "RootStackName",
        Type="String",
        Description="The root stack name",
    )
)

ApiSubnet2 = t.add_parameter(
    Parameter(
        "ApiSubnet2",
        Type="String",
        Description="Second private VPC subnet ID for the api app.",
    )
)

ApiSubnet1 = t.add_parameter(
    Parameter(
        "ApiSubnet1",
        Type="String",
        Description="First private VPC subnet ID for the api app.",
    )
)

LaunchConfig = t.add_resource(
    LaunchConfiguration(
        "LaunchConfiguration",
        Metadata=autoscaling.Metadata(
            cloudformation.Init(
                {
                    "config": cloudformation.InitConfig(
                        files=cloudformation.InitFiles(
                            {
                                "/etc/rsyslog.d/20-somethin.conf": cloudformation.InitFile(
                                    source=Join(
                                        "",
                                        [
                                            "http://",
                                            Ref(DeployBucket),
                                            ".s3.amazonaws.com/stacks/",
                                            Ref(RootStackName),
                                            "/env/etc/rsyslog.d/20-somethin.conf",
                                        ],
                                    ),
                                    mode="000644",
                                    owner="root",
                                    group="root",
                                    authentication="DeployUserAuth",
                                )
                            }
                        ),
                        services={
                            "sysvinit": cloudformation.InitServices(
                                {
                                    "rsyslog": cloudformation.InitService(
                                        enabled=True,
                                        ensureRunning=True,
                                        files=["/etc/rsyslog.d/20-somethin.conf"],
                                    )
                                }
                            )
                        },
                    )
                }
            ),
            cloudformation.Authentication(
                {
                    "DeployUserAuth": cloudformation.AuthenticationBlock(
                        type="S3",
                        accessKeyId=Ref(DeployUserAccessKey),
                        secretKey=Ref(DeployUserSecretKey),
                    )
                }
            ),
        ),
        UserData=Base64(
            Join(
                "",
                [
                    "#!/bin/bash\n",
                    "cfn-signal -e 0",
                    "    --resource AutoscalingGroup",
                    "    --stack ",
                    Ref("AWS::StackName"),
                    "    --region ",
                    Ref("AWS::Region"),
                    "\n",
                ],
            )
        ),
        ImageId=Ref(AmiId),
        KeyName=Ref(KeyName),
        BlockDeviceMappings=[
            ec2.BlockDeviceMapping(
                DeviceName="/dev/sda1", Ebs=ec2.EBSBlockDevice(VolumeSize="8")
            ),
        ],
        SecurityGroups=[Ref(SecurityGroup)],
        InstanceType="t2.micro",
    )
)

LoadBalancer = t.add_resource(
    LoadBalancer(
        "LoadBalancer",
        ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
            Enabled=True,
            Timeout=120,
        ),
        Subnets=[Ref(PublicSubnet1), Ref(PublicSubnet2)],
        HealthCheck=elb.HealthCheck(
            Target="HTTP:80/",
            HealthyThreshold="5",
            UnhealthyThreshold="2",
            Interval="20",
            Timeout="15",
        ),
        Listeners=[
            elb.Listener(
                LoadBalancerPort="443",
                InstancePort="80",
                Protocol="HTTPS",
                InstanceProtocol="HTTP",
                SSLCertificateId=Ref(SSLCertificateId),
            ),
        ],
        CrossZone=True,
        SecurityGroups=[Ref(LoadBalancerSecurityGroup)],
        LoadBalancerName="api-lb",
        Scheme="internet-facing",
    )
)

AutoscalingGroup = t.add_resource(
    AutoScalingGroup(
        "AutoscalingGroup",
        DesiredCapacity=Ref(ScaleCapacity),
        Tags=[Tag("Environment", Ref(EnvType), True)],
        LaunchConfigurationName=Ref(LaunchConfig),
        MinSize=Ref(ScaleCapacity),
        MaxSize=Ref(ScaleCapacity),
        VPCZoneIdentifier=[Ref(ApiSubnet1), Ref(ApiSubnet2)],
        LoadBalancerNames=[Ref(LoadBalancer)],
        AvailabilityZones=[Ref(VPCAvailabilityZone1), Ref(VPCAvailabilityZone2)],
        HealthCheckType="EC2",
        UpdatePolicy=UpdatePolicy(
            AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
                WillReplace=True,
            ),
            AutoScalingRollingUpdate=AutoScalingRollingUpdate(
                PauseTime="PT5M",
                MinInstancesInService="1",
                MaxBatchSize="1",
                WaitOnResourceSignals=True,
            ),
        ),
    )
)

print(t.to_json())
