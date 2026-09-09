terraform {
  required_providers {
    local  = { source = "hashicorp/local",  version = "~> 2.5" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}
resource "local_file" "config" {
  filename = "${path.module}/out/app.conf"
  content  = var.config
}
resource "random_password" "db" {
  length  = var.password_length
  special = true
}
variable "config" {
  type    = string
  default = "listen = 127.0.0.1"
}
variable "password_length" {
  type    = number
  default = 20
}
