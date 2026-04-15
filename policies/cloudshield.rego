package cloudshield

deny[msg] {
    some i
    input.s3_buckets[i].public == true
    msg = "S3 bucket is public"
}

deny[msg] {
    some i
    not input.s3_buckets[i].encryption
    msg = "S3 encryption disabled"
}

deny[msg] {
    some i
    input.iam_roles[i].policy == "*:*"
    msg = "IAM role has full access"
}

deny[msg] {
    some sg
    some rule
    input.security_groups[sg].inbound[rule].cidr == "0.0.0.0/0"
    msg = "Security group open to world"
}
