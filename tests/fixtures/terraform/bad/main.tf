# FAKE resources for tests only. Deliberately insecure. Never deploy.

resource "aws_s3_bucket" "public" {
  bucket = "sentinel-fake-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "sentinel-fake-open-ssh"
  description = "FAKE: SSH open to the world"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

resource "azurerm_storage_account" "http_allowed" {
  name                      = "sentinelfakestorage"
  resource_group_name       = "sentinel-fake-rg"
  location                  = "westeurope"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  enable_https_traffic_only = false
}
