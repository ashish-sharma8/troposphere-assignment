This is a script to genrate Cloudformation templates using troposphere.

In order to run the scripts run the following commands:
pip install troposphere
python templategenerator.py

templategenerator.py generates:
- VPC with public and a private subnet
- Application Load Balancer
- EC2 instance running nginx image and serving traffic
- Cloudwatch monitoring for an instance 
- Cloudwatch alarm when EC2 CPU utilisation > 50%
