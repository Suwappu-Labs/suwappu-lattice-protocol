variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "ltp-observability"
}

variable "tags" {
  type = map(string)
  default = {
    "ltp:owner"       = "platform"
    "ltp:cost-center" = "ltp-observability"
    "ltp:repo"        = "suwappu-lattice-protocol"
  }
}
