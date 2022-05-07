terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

// https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key
resource "aws_kms_key" "test" {
  description              = "go-sql-crypter test key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  deletion_window_in_days  = 7

  tags = {
    Owner = "github.com/bincyber/go-sqlcrypter"
    Env   = "test"
    Usage = "go-sql-crypter"
  }
}

resource "aws_kms_alias" "test" {
  name          = "alias/go-sql-crypter"
  target_key_id = aws_kms_key.test.key_id
}

output "key_id" {
  value = aws_kms_key.test.id
}

output "key_arn" {
  value = aws_kms_key.test.arn
}
