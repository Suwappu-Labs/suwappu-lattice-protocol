# LTP production VPC.
#
# Layout:
#   - One /16 split into 2x /20 private + 2x /20 public per AZ
#   - One NAT gateway per AZ (HA; pay-for-it because the alternative is
#     a single NAT and an unplanned outage on its AZ)
#   - Private subnets are tagged for the AWS Load Balancer Controller
#     and Karpenter (kubernetes.io/role/internal-elb = 1)
#   - Public subnets are tagged for internet-facing ALBs
#     (kubernetes.io/role/elb = 1)
#
# Reference: AWS EKS best-practices guide (cluster networking section).

locals {
  az_count      = length(var.azs)
  private_cidrs = [for i in range(local.az_count) : cidrsubnet(var.cidr, 4, i)]
  public_cidrs  = [for i in range(local.az_count) : cidrsubnet(var.cidr, 4, i + local.az_count)]

  common_tags = merge(
    {
      "ltp:module" = "vpc"
      "ltp:env"    = var.name
    },
    var.tags,
  )
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = var.name
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(local.common_tags, {
    Name = "${var.name}-igw"
  })
}

resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = var.azs[count.index]

  tags = merge(local.common_tags, {
    Name                                = "${var.name}-private-${var.azs[count.index]}"
    "kubernetes.io/role/internal-elb"   = "1"
    "kubernetes.io/cluster/${var.name}" = "shared"
  })
}

resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name                                = "${var.name}-public-${var.azs[count.index]}"
    "kubernetes.io/role/elb"            = "1"
    "kubernetes.io/cluster/${var.name}" = "shared"
  })
}

resource "aws_eip" "nat" {
  count = local.az_count

  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${var.name}-nat-${var.azs[count.index]}"
  })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  count = local.az_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(local.common_tags, {
    Name = "${var.name}-nat-${var.azs[count.index]}"
  })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-public"
  })
}

resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count = local.az_count

  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[count.index].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.name}-private-${var.azs[count.index]}"
  })
}

resource "aws_route_table_association" "private" {
  count = local.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
