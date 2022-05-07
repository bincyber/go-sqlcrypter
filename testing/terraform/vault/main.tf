terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "3.6.0"
    }
  }
}

provider "vault" {
  address          = "http://0.0.0.0:8200"
  token            = "vaultroottoken"
  skip_child_token = true
}

resource "vault_mount" "test" {
  path                      = "transit"
  type                      = "transit"
  description               = "go-sqlcrypter"
  default_lease_ttl_seconds = 300
  max_lease_ttl_seconds     = 300
}


resource "vault_transit_secret_backend_key" "test" {
  backend          = vault_mount.test.path
  name             = "go-sqlcrypter"
  type             = "aes256-gcm96"
  derived          = false
  deletion_allowed = true
}

output "mount" {
  value = vault_mount.test.id
}

output "key" {
  value = vault_transit_secret_backend_key.test.name
}
