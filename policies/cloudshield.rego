package cloudshield

import rego.v1

# ── S3 Bucket Policies ──────────────────────────────────────────────

deny contains msg if {
    bucket := input.s3_buckets[_]
    bucket.public == true
    msg := sprintf("S3 bucket '%v' is publicly accessible", [bucket.name])
}

deny contains msg if {
    bucket := input.s3_buckets[_]
    bucket.acl == "public-read"
    msg := sprintf("S3 bucket '%v' has public-read ACL", [bucket.name])
}

deny contains msg if {
    bucket := input.s3_buckets[_]
    bucket.acl == "public-read-write"
    msg := sprintf("S3 bucket '%v' has public-read-write ACL — critical exposure", [bucket.name])
}

deny contains msg if {
    bucket := input.s3_buckets[_]
    bucket.encryption.enabled == false
    msg := sprintf("S3 bucket '%v' does not have server-side encryption enabled", [bucket.name])
}

deny contains msg if {
    bucket := input.s3_buckets[_]
    bucket.logging.enabled == false
    msg := sprintf("S3 bucket '%v' does not have access logging enabled", [bucket.name])
}

# ── IAM Policies ─────────────────────────────────────────────────────

deny contains msg if {
    role := input.iam_roles[_]
    role.mfa_required == false
    msg := sprintf("IAM role '%v' does not require MFA", [role.name])
}

deny contains msg if {
    role := input.iam_roles[_]
    policy := role.policies[_]
    policy.action == "*"
    policy.resource == "*"
    msg := sprintf("IAM role '%v' has wildcard action '*' on all resources '*'", [role.name])
}

# ── Security Groups ───────────────────────────────────────────────────

deny contains msg if {
    sg := input.security_groups[_]
    rule := sg.ingress_rules[_]
    rule.cidr == "0.0.0.0/0"
    msg := sprintf("Security group '%v' allows unrestricted inbound access on port %v", [sg.name, rule.port])
}

deny contains msg if {
    sg := input.security_groups[_]
    rule := sg.ingress_rules[_]
    rule.cidr == "0.0.0.0/0"
    rule.port == 22
    msg := sprintf("Security group '%v' exposes SSH (port 22) to the internet — CRITICAL", [sg.name])
}

# ── Container Policies ────────────────────────────────────────────────

deny contains msg if {
    container := input.containers[_]
    container.privileged == true
    msg := sprintf("Container '%v' is running in privileged mode — host breakout risk", [container.name])
}

deny contains msg if {
    container := input.containers[_]
    container.run_as_root == true
    msg := sprintf("Container '%v' runs as root user, violating least privilege", [container.name])
}

# ── RDS Policies ──────────────────────────────────────────────────────

deny contains msg if {
    db := input.rds_instances[_]
    db.publicly_accessible == true
    msg := sprintf("RDS instance '%v' is publicly accessible from the internet", [db.identifier])
}

deny contains msg if {
    db := input.rds_instances[_]
    db.deletion_protection == false
    msg := sprintf("RDS instance '%v' has deletion protection disabled", [db.identifier])
}

# ── VPC Flow Logs ─────────────────────────────────────────────────────

deny contains msg if {
    vpc := input.vpcs[_]
    vpc.flow_logs_enabled == false
    msg := sprintf("VPC '%v' does not have flow logging enabled — network activity unmonitored", [vpc.id])
}
