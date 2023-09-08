data "aws_availability_zones" "available" {}

locals {
    environment = "test"
    name   = "payplus-${local.environment}-msk-01"

    vpc_cidr = "192.168.0.0/16"
    azs      = slice(data.aws_availability_zones.available.names, 0, 3)

}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.vpc_cidr

  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 3)]

  create_database_subnet_group = true
  enable_nat_gateway           = true
  single_nat_gateway           = true

}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.0"

  name        = local.name
  description = "Security group for ${local.name}"
  vpc_id      =  module.vpc.vpc_id

}

module "msk_cluster" {
  source = "terraform-aws-modules/msk-kafka-cluster/aws"

  name                   = local.name
  kafka_version          = "2.8.1"
  number_of_broker_nodes = 3
  # enhanced_monitoring    = "PER_TOPIC_PER_PARTITION" #may be need to comment

  broker_node_client_subnets  =  module.vpc.private_subnets
  broker_node_instance_type   = "kafka.t3.small"
  broker_node_security_groups = [module.security_group.security_group_id]
  broker_node_storage_info = {
    ebs_storage_info = { volume_size = 100 }
  }

  encryption_in_transit_client_broker = "TLS_PLAINTEXT"
  encryption_in_transit_in_cluster    = true

  configuration_name        = "payplus-${local.environment}-msk-conf"
  configuration_description = ""
  configuration_server_properties = {
    "auto.create.topics.enable"=true
    "default.replication.factor"=1
    "min.insync.replicas"=1
    "num.io.threads"=8
    "num.network.threads"=5
    "num.partitions"=1
    "num.replica.fetchers"=2
    "replica.lag.time.max.ms"=30000
    "socket.receive.buffer.bytes"=102400
    "socket.request.max.bytes"=1395725856
    "socket.send.buffer.bytes"=102400
    "unclean.leader.election.enable"=true
    "zookeeper.session.timeout.ms"=18000
  }

  jmx_exporter_enabled    = false
  node_exporter_enabled   = false
  cloudwatch_logs_enabled = true
  s3_logs_enabled         = false

  client_authentication = {
    sasl = { iam = true }
    unauthenticated = true 
  }
  create_scram_secret_association  = false
}


# S3 bucket for custom plugin 

resource "aws_s3_bucket" "custom_connector_plugin" {
  bucket = "payplus-${local.environment}-msk-connect"
}

resource "aws_s3_bucket_object" "custom_connector_jar" {
  bucket = aws_s3_bucket.custom_connector_plugin.id
  key    = "custom-kafka-connect.zip"
  source = "./custom-kafka-connect.zip"
}

# Clustom plugin for MSK connector

resource "aws_mskconnect_custom_plugin" "s3" {
  name         = "payplus-${local.environment}-msk-connect-plugin"
  content_type = "ZIP"
  location {
    s3 {
      bucket_arn = aws_s3_bucket.custom_connector_plugin.arn
      file_key   = aws_s3_bucket_object.custom_connector_jar.key
    }
  }
}


# Role for connector

resource "aws_iam_role" "connector_role" {
  name = "payplus-${local.environment}-msk-connector-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "kafkaconnect.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

# Policy for coonector role
resource "aws_iam_role_policy" "connector_role_policy1" {
  name = "payplus-${local.environment}-msk-01-policy"
  role = aws_iam_role.connector_role.id
  policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": "arn:aws:ec2:*:*:network-interface/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInterface"
            ],
            "Resource": [
                "arn:aws:ec2:*:*:subnet/*",
                "arn:aws:ec2:*:*:security-group/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags"
            ],
            "Resource": "arn:aws:ec2:*:*:network-interface/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeNetworkInterfaces",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:AttachNetworkInterface",
                "ec2:DetachNetworkInterface",
                "ec2:DeleteNetworkInterface"
            ],
            "Resource": "arn:aws:ec2:*:*:network-interface/*"
        }
    ]
  })
}

resource "aws_iam_role_policy" "connector_role_policy2" {
  name = "payplus-${local.environment}-msk-02-policy"
  role = aws_iam_role.connector_role.id
  policy = jsonencode({
         "Version": "2012-10-17",
         "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "kafka-cluster:DescribeTopicDynamicConfiguration",
                "kafka-cluster:DescribeCluster",
                "kafka-cluster:ReadData",
                "kafka-cluster:DescribeTopic",
                "kafka-cluster:DescribeTransactionalId",
                "kafka-cluster:DescribeGroup",
                "kafka-cluster:DescribeClusterDynamicConfiguration"
            ],
            "Resource": "*"
        }
    ]
  })
}

resource "aws_iam_policy_attachment" "existing_role_policy" {
  name       = "attach-existing-role-policy"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"  # Replace with the actual policy ARN
  roles      = [aws_iam_role.connector_role.name]
}

# Log group for MSK connector

resource "aws_cloudwatch_log_group" "connector_log_group" {
  name = "payplus-${local.environment}-msk-loggroup"
}

# MSK Connector 

resource "aws_mskconnect_connector" "connector" {
  name = "payplus-${local.environment}-msk-connector"
  kafkaconnect_version = "2.7.1"
  capacity {
    provisioned_capacity {
      mcu_count = 1
      worker_count = 1
      # min_worker_count = 1
      # max_worker_count = 2
      # scale_in_policy {
      #   cpu_utilization_percentage = 20
      # }
      # scale_out_policy {
      #   cpu_utilization_percentage = 80
      # }
    }
  }
  connector_configuration = {
    "connector.class"="io.debezium.connector.postgresql.PostgresConnector"
    "database.user"="debezium" #change here
    "database.dbname"="mpos"   #change here
    "database.server.id"="123456"
    "tasks.max"="1"
    "transforms"="unwrap"
    "database.server.name"="payplus-dev2-rds"   #change here
    "internal.key.converter.schemas.enable"="false"
    "plugin.name"="pgoutput"
    "database.port"="5432"
    "internal.key.converter"="org.apache.kafka.connect.json.JsonConverter"
    "key.converter.schemas.enable"="false"
    "topic.prefix"="postgres"
    "database.hostname"="payplus-dev2-rds.cbasklme8dw6.ap-south-1.rds.amazonaws.com"  # Change here
    "database.password"="mpos"   # Change here
    "internal.value.converter.schemas.enable"="false"
    "internal.value.converter"="org.apache.kafka.connect.json.JsonConverter"
    "value.converter.schemas.enable"="false"
    "transforms.unwrap.type"="io.debezium.transforms.ExtractNewRecordState"
    "table.include.list"="businesstxn.mpos_transaction_audit"
    "value.converter"="org.apache.kafka.connect.json.JsonConverter"
    "database.whitelist"="mpos"
    "key.converter"="org.apache.kafka.connect.json.JsonConverter"
  }
  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = module.msk_cluster.bootstrap_brokers_tls
      vpc {
        security_groups = ["${module.security_group.security_group_id}"]  #same as MSK cluster
        subnets = [module.vpc.private_subnets[0],
                  module.vpc.private_subnets[1],
                  module.vpc.private_subnets[2]]
      }
    }
  }
  kafka_cluster_client_authentication {
    authentication_type = "NONE"
  }
  kafka_cluster_encryption_in_transit {
    encryption_type = "PLAINTEXT"
  }
  plugin {
    custom_plugin {
      arn = aws_mskconnect_custom_plugin.s3.arn
      revision = aws_mskconnect_custom_plugin.s3.latest_revision
    }
  }
  // Support for logging
  log_delivery {
    worker_log_delivery {
      cloudwatch_logs {
        enabled = true
        log_group = aws_cloudwatch_log_group.connector_log_group.name
      }
    }
  }  
  service_execution_role_arn = aws_iam_role.connector_role.arn
}