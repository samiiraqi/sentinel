# FAKE resources for tests only. A small, locked-down example.

resource "aws_kms_key" "ebs" {
  description             = "FAKE: key for EBS encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAccountAdmin"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::000000000000:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}
