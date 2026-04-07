terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. Base VPC and Subnet Configuration
resource "aws_vpc" "netguard_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "SentinAI-VPC"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.netguard_vpc.id

  tags = {
    Name = "SentinAI-IGW"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.netguard_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "SentinAI-Public-Subnet"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.netguard_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "SentinAI-Public-RT"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# 2. Security Groups
resource "aws_security_group" "netguard_core_sg" {
  name        = "NetGuard-Core-SG"
  description = "Backend security group for API, VXLAN, and MongoDB"
  vpc_id      = aws_vpc.netguard_vpc.id

  # API Access
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH Access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # Traffic Mirroring (VXLAN)
  ingress {
    from_port   = 4789
    to_port     = 4789
    protocol    = "udp"
    cidr_blocks = [aws_vpc.netguard_vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SentinAI-Core-SG"
  }
}

resource "aws_security_group" "target_server_sg" {
  name        = "Target-Server-SG"
  description = "Vulnerable Target Security Group (For attacking/testing)"
  vpc_id      = aws_vpc.netguard_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Open for simulated dictionary attacks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SentinAI-Target-SG"
  }
}

# 3. Compute Instances
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "netguard_core" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.netguard_core_sg.id]
  key_name      = var.ssh_key_name

  tags = {
    Name = "NetGuard-Core-Engine"
  }

  # Ensure Traffic Mirror setup occurs post-creation
  user_data = <<-EOF
              #!/bin/bash
              # Minimal setup required to handle VXLAN mirroring
              apt-get update -y
              apt-get install -y python3-pip npm net-tools tcpdump mongodb-org
              # Create a service file to persistently raise the VXLAN interface
              EOF
}

resource "aws_instance" "target_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.target_server_sg.id]
  key_name      = var.ssh_key_name

  tags = {
    Name = "Victim-Target-Server"
  }
}

# 4. VPC Traffic Mirroring Logic
resource "aws_ec2_traffic_mirror_target" "core_target" {
  network_interface_id = aws_instance.netguard_core.primary_network_interface_id
  description          = "NetGuard Capture Interface"
  
  tags = {
    Name = "NetGuard-Inspection-Target"
  }
}

resource "aws_ec2_traffic_mirror_filter" "catch_all" {
  description      = "SentinAI Global Filter"
  network_services = ["amazon-dns"]
}

resource "aws_ec2_traffic_mirror_filter_rule" "inbound_rule" {
  description              = "Allow all inbound"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.catch_all.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_number              = 100
  rule_action              = "accept"
  traffic_direction        = "ingress"
}

resource "aws_ec2_traffic_mirror_filter_rule" "outbound_rule" {
  description              = "Allow all outbound"
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.catch_all.id
  destination_cidr_block   = "0.0.0.0/0"
  source_cidr_block        = "0.0.0.0/0"
  rule_number              = 100
  rule_action              = "accept"
  traffic_direction        = "egress"
}

resource "aws_ec2_traffic_mirror_session" "mirror_link" {
  description              = "Target to Engine Link"
  network_interface_id     = aws_instance.target_server.primary_network_interface_id
  traffic_mirror_filter_id = aws_ec2_traffic_mirror_filter.catch_all.id
  traffic_mirror_target_id = aws_ec2_traffic_mirror_target.core_target.id
  session_number           = 1
}

# 5. Outputs
output "netguard_core_public_ip" {
  value = aws_instance.netguard_core.public_ip
}

output "target_server_public_ip" {
  value = aws_instance.target_server.public_ip
}

output "target_server_private_ip" {
  value = aws_instance.target_server.private_ip
}
