// ─── Types ───────────────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ResourceType = 'container' | 'storage' | 'iam' | 'network' | 'compute';
export type FindingStatus = 'open' | 'in_progress' | 'resolved';
export type ComplianceFramework = 'hipaa' | 'nist' | 'iso';

export interface Finding {
    id: string;
    cve?: string;
    title: string;
    description: string;
    severity: Severity;
    resourceType: ResourceType;
    resource: string;
    riskScore: number;
    status: FindingStatus;
    framework: ComplianceFramework[];
    discoveredAt: string;
    remediationCommand?: string;
    remediationTerraform?: string;
    mitre?: {
        tactic: string;
        technique: string;
        id: string;
    };
    cvssScore?: number;
    affectedImage?: string;
    tags: string[];
}

export interface ComplianceControl {
    id: string;
    framework: ComplianceFramework;
    controlId: string;
    title: string;
    description: string;
    status: 'pass' | 'fail' | 'partial';
    evidence: string[];
    findingIds: string[];
}

export interface TrendDataPoint {
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
}

// ─── Mock Findings ────────────────────────────────────────────────────────────

export const mockFindings: Finding[] = [
    {
        id: 'f-001',
        cve: 'CVE-2024-21626',
        title: 'Container Escape via runc Vulnerability',
        description: 'A critical container escape vulnerability in runc allows attackers to gain root access on the host system from within a container.',
        severity: 'critical',
        resourceType: 'container',
        resource: 'production/api-server:v2.1.3',
        riskScore: 9.8,
        status: 'open',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-20T08:23:11Z',
        remediationCommand: 'docker pull api-server:v2.1.4\ndocker stop production-api\ndocker run -d --name production-api api-server:v2.1.4',
        cvssScore: 9.8,
        affectedImage: 'api-server:v2.1.3',
        tags: ['container', 'rce', 'critical'],
    },
    {
        id: 'f-002',
        cve: 'CVE-2024-3094',
        title: 'XZ Utils Backdoor in Base Image',
        description: 'Malicious code found in XZ Utils versions 5.6.0 and 5.6.1 that could allow unauthorized remote access via sshd.',
        severity: 'critical',
        resourceType: 'container',
        resource: 'staging/worker:debian-bookworm',
        riskScore: 10.0,
        status: 'in_progress',
        framework: ['nist', 'iso'],
        discoveredAt: '2024-02-19T11:05:32Z',
        remediationCommand: 'apt-get update && apt-get install --only-upgrade xz-utils\n# Or rebuild from updated base image:\ndocker build --no-cache -t worker:safe .',
        cvssScore: 10.0,
        affectedImage: 'debian:bookworm',
        tags: ['supply-chain', 'backdoor', 'critical'],
    },
    {
        id: 'f-003',
        title: 'S3 Bucket Publicly Accessible',
        description: 'S3 bucket "prod-customer-data" has a public ACL policy allowing unauthenticated read access to sensitive customer records.',
        severity: 'critical',
        resourceType: 'storage',
        resource: 'aws::s3::prod-customer-data',
        riskScore: 9.2,
        status: 'open',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-21T14:30:00Z',
        remediationCommand: 'aws s3api put-bucket-acl --bucket prod-customer-data --acl private\naws s3api put-public-access-block --bucket prod-customer-data --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
        remediationTerraform: `resource "aws_s3_bucket_public_access_block" "prod_customer_data" {
  bucket = aws_s3_bucket.prod_customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
        tags: ['s3', 'data-exposure', 'pci-dss'],
    },
    {
        id: 'f-004',
        title: 'IAM Role with Wildcard Permissions',
        description: 'IAM role "LambdaExecutionRole" has Action: "*" and Resource: "*" granting unrestricted access to all AWS services.',
        severity: 'critical',
        resourceType: 'iam',
        resource: 'aws::iam::role/LambdaExecutionRole',
        riskScore: 9.5,
        status: 'open',
        framework: ['nist', 'iso'],
        discoveredAt: '2024-02-18T09:12:45Z',
        remediationTerraform: `resource "aws_iam_role_policy" "lambda_policy" {
  role = aws_iam_role.lambda_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject", "logs:CreateLogGroup"]
      Resource = ["\${aws_s3_bucket.data.arn}/*"]
    }]
  })
}`,
        tags: ['iam', 'least-privilege', 'privilege-escalation'],
    },
    {
        id: 'f-005',
        cve: 'CVE-2023-44487',
        title: 'HTTP/2 Rapid Reset Attack (NGINX)',
        description: 'NGINX version < 1.25.3 vulnerable to HTTP/2 Rapid Reset DoS attack that can overwhelm servers.',
        severity: 'high',
        resourceType: 'container',
        resource: 'production/nginx:1.24.0',
        riskScore: 7.5,
        status: 'resolved',
        framework: ['nist'],
        discoveredAt: '2024-02-15T16:45:00Z',
        remediationCommand: 'docker pull nginx:1.25.4\ndocker service update --image nginx:1.25.4 production_nginx',
        cvssScore: 7.5,
        affectedImage: 'nginx:1.24.0',
        tags: ['dos', 'http2', 'nginx'],
    },
    {
        id: 'f-006',
        title: 'Security Group Allows Unrestricted Inbound SSH',
        description: 'Security group sg-0a1b2c3d allows SSH (port 22) from 0.0.0.0/0 exposing instances to the public internet.',
        severity: 'high',
        resourceType: 'network',
        resource: 'aws::ec2::security-group/sg-0a1b2c3d',
        riskScore: 8.1,
        status: 'open',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-20T10:22:33Z',
        remediationTerraform: `resource "aws_security_group_rule" "ssh_restricted" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # VPN CIDR only
  security_group_id = aws_security_group.main.id
}`,
        tags: ['network', 'ssh', 'exposure'],
    },
    {
        id: 'f-007',
        cve: 'CVE-2024-23897',
        title: 'Jenkins Arbitrary File Read',
        description: 'Jenkins versions up to 2.441 allow unauthenticated attackers to read arbitrary files from the Jenkins controller file system.',
        severity: 'high',
        resourceType: 'compute',
        resource: 'production/jenkins:2.430',
        riskScore: 7.9,
        status: 'in_progress',
        framework: ['nist', 'iso'],
        discoveredAt: '2024-02-17T13:55:00Z',
        remediationCommand: 'docker pull jenkins/jenkins:2.442-lts\ndocker stop jenkins && docker rm jenkins\ndocker run -d -p 8080:8080 --name jenkins jenkins/jenkins:2.442-lts',
        cvssScore: 9.8,
        affectedImage: 'jenkins/jenkins:2.430',
        tags: ['jenkins', 'rce', 'ci-cd'],
    },
    {
        id: 'f-008',
        title: 'RDS Instance Without Encryption at Rest',
        description: 'RDS PostgreSQL instance "prod-db-primary" does not have encryption at rest enabled, violating HIPAA and compliance policies.',
        severity: 'high',
        resourceType: 'storage',
        resource: 'aws::rds::db-instance/prod-db-primary',
        riskScore: 7.2,
        status: 'open',
        framework: ['hipaa', 'nist'],
        discoveredAt: '2024-02-16T07:11:22Z',
        remediationTerraform: `resource "aws_db_instance" "prod_primary" {
  identifier        = "prod-db-primary"
  engine            = "postgres"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
  # ... other config
}`,
        tags: ['rds', 'encryption', 'hipaa'],
    },
    {
        id: 'f-009',
        title: 'CloudTrail Logging Disabled in Region',
        description: 'AWS CloudTrail is not enabled in us-west-2 region, preventing audit trail of API activity.',
        severity: 'high',
        resourceType: 'iam',
        resource: 'aws::cloudtrail::us-west-2',
        riskScore: 6.8,
        status: 'open',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-19T15:30:00Z',
        remediationCommand: 'aws cloudtrail create-trail --name prod-trail --s3-bucket-name cloudtrail-logs-prod --is-multi-region-trail\naws cloudtrail start-logging --name prod-trail',
        tags: ['cloudtrail', 'audit', 'logging'],
    },
    {
        id: 'f-010',
        cve: 'CVE-2024-1234',
        title: 'Log4Shell Vulnerable Dependency',
        description: 'log4j-core version 2.14.1 detected, vulnerable to remote code execution via JNDI lookup.',
        severity: 'critical',
        resourceType: 'container',
        resource: 'production/payment-service:1.0.2',
        riskScore: 10.0,
        status: 'resolved',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-10T08:00:00Z',
        remediationCommand: '# Update pom.xml:\n# <log4j.version>2.21.0</log4j.version>\nmvn clean package -DskipTests\ndocker build -t payment-service:1.0.3 .',
        cvssScore: 10.0,
        tags: ['log4j', 'rce', 'java', 'critical'],
    },
    {
        id: 'f-011',
        title: 'Container Running as Root',
        description: 'Container "auth-service" is running as root user (UID 0), violating CIS Docker Benchmark 4.1.',
        severity: 'medium',
        resourceType: 'container',
        resource: 'production/auth-service:latest',
        riskScore: 5.5,
        status: 'open',
        framework: ['nist', 'iso'],
        discoveredAt: '2024-02-21T09:00:00Z',
        remediationCommand: '# Add to Dockerfile:\nRUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser',
        tags: ['container', 'privilege', 'cis'],
    },
    {
        id: 'f-012',
        title: 'MFA Not Enforced for IAM Users',
        description: '14 IAM users do not have MFA enabled, including 3 with admin-level access.',
        severity: 'high',
        resourceType: 'iam',
        resource: 'aws::iam::users (14 affected)',
        riskScore: 7.8,
        status: 'in_progress',
        framework: ['hipaa', 'nist', 'iso'],
        discoveredAt: '2024-02-20T11:30:00Z',
        remediationCommand: '# Enable MFA for each user via AWS Console or:\naws iam create-virtual-mfa-device --virtual-mfa-device-name UserMFA\naws iam enable-mfa-device --user-name USERNAME --serial-number arn:...',
        tags: ['iam', 'mfa', 'authentication'],
    },
    {
        id: 'f-013',
        title: 'Load Balancer Without HTTPS Redirect',
        description: 'Application Load Balancer "prod-alb" serves traffic on HTTP port 80 without redirecting to HTTPS.',
        severity: 'medium',
        resourceType: 'network',
        resource: 'aws::elbv2::prod-alb',
        riskScore: 5.0,
        status: 'open',
        framework: ['hipaa', 'iso'],
        discoveredAt: '2024-02-18T14:15:00Z',
        remediationTerraform: `resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.prod.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}`,
        tags: ['network', 'tls', 'https'],
    },
    {
        id: 'f-014',
        title: 'EKS Cluster API Public Endpoint',
        description: 'EKS cluster "prod-cluster" has public API endpoint enabled without IP restrictions.',
        severity: 'high',
        resourceType: 'compute',
        resource: 'aws::eks::cluster/prod-cluster',
        riskScore: 7.0,
        status: 'open',
        framework: ['nist', 'iso'],
        discoveredAt: '2024-02-21T16:00:00Z',
        remediationTerraform: `resource "aws_eks_cluster" "prod" {
  name = "prod-cluster"
  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = ["203.0.113.0/24"]  # Office IP
  }
}`,
        tags: ['eks', 'kubernetes', 'exposure'],
    },
    {
        id: 'f-015',
        title: 'Lambda Function with Deprecated Runtime',
        description: '7 Lambda functions using Node.js 16.x runtime which reached end-of-life.',
        severity: 'medium',
        resourceType: 'compute',
        resource: 'aws::lambda (7 functions)',
        riskScore: 4.5,
        status: 'open',
        framework: ['nist'],
        discoveredAt: '2024-02-17T10:00:00Z',
        remediationCommand: 'aws lambda update-function-configuration --function-name FUNCTION_NAME --runtime nodejs20.x',
        tags: ['lambda', 'runtime', 'eol'],
    },
];

// ─── Dashboard Stats ──────────────────────────────────────────────────────────

export const dashboardStats = {
    totalScans: 1500,
    criticalFindings: 23,
    avgRemediationHours: 21,
    openIssues: 142,
    resolvedThisWeek: 38,
    complianceScore: 72,
};

// ─── Risk Trend (30 days) ─────────────────────────────────────────────────────

export const riskTrendData: TrendDataPoint[] = [
    { date: 'Jan 24', critical: 18, high: 42, medium: 67, low: 95 },
    { date: 'Jan 27', critical: 21, high: 45, medium: 71, low: 98 },
    { date: 'Jan 30', critical: 19, high: 43, medium: 68, low: 96 },
    { date: 'Feb 2', critical: 24, high: 48, medium: 72, low: 100 },
    { date: 'Feb 5', critical: 22, high: 46, medium: 70, low: 97 },
    { date: 'Feb 8', critical: 20, high: 44, medium: 66, low: 93 },
    { date: 'Feb 11', critical: 17, high: 40, medium: 63, low: 90 },
    { date: 'Feb 14', critical: 15, high: 38, medium: 60, low: 88 },
    { date: 'Feb 17', critical: 19, high: 42, medium: 64, low: 91 },
    { date: 'Feb 20', critical: 23, high: 47, medium: 69, low: 94 },
    { date: 'Feb 23', critical: 23, high: 45, medium: 67, low: 92 },
];

// ─── Compliance Controls ─────────────────────────────────────────────────────

export const complianceControls: ComplianceControl[] = [
    // HIPAA
    { id: 'h-1', framework: 'hipaa', controlId: '164.312(a)(1)', title: 'Access Control', description: 'Implement technical policies for electronic PHI access.', status: 'partial', evidence: ['IAM policies reviewed', 'MFA not enforced for 14 users'], findingIds: ['f-012'] },
    { id: 'h-2', framework: 'hipaa', controlId: '164.312(a)(2)(iv)', title: 'Encryption & Decryption', description: 'Implement mechanism to encrypt and decrypt ePHI.', status: 'fail', evidence: ['RDS prod-db-primary unencrypted'], findingIds: ['f-008'] },
    { id: 'h-3', framework: 'hipaa', controlId: '164.312(b)', title: 'Audit Controls', description: 'Implement hardware/software activity auditing.', status: 'fail', evidence: ['CloudTrail disabled in us-west-2'], findingIds: ['f-009'] },
    { id: 'h-4', framework: 'hipaa', controlId: '164.312(c)(1)', title: 'Integrity', description: 'Implement policies to protect ePHI from improper alteration.', status: 'pass', evidence: ['S3 versioning enabled', 'RDS automated backups on'], findingIds: [] },
    { id: 'h-5', framework: 'hipaa', controlId: '164.312(e)(1)', title: 'Transmission Security', description: 'Implement security measures to guard against unauthorized access to ePHI in transit.', status: 'partial', evidence: ['ALB HTTP redirect missing'], findingIds: ['f-013'] },
    { id: 'h-6', framework: 'hipaa', controlId: '164.308(a)(1)', title: 'Security Management Process', description: 'Implement policies to prevent, detect, contain, and correct security violations.', status: 'pass', evidence: ['Security scanning pipeline active', 'Incident response plan documented'], findingIds: [] },

    // NIST
    { id: 'n-1', framework: 'nist', controlId: 'AC-2', title: 'Account Management', description: 'Manage information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.', status: 'partial', evidence: ['14 IAM users without MFA'], findingIds: ['f-012'] },
    { id: 'n-2', framework: 'nist', controlId: 'AC-3', title: 'Access Enforcement', description: 'Enforce approved authorizations for logical access to information.', status: 'fail', evidence: ['IAM role with wildcard permissions'], findingIds: ['f-004'] },
    { id: 'n-3', framework: 'nist', controlId: 'AU-2', title: 'Audit Events', description: 'Identify the types of events that the system is capable of logging.', status: 'fail', evidence: ['CloudTrail disabled in us-west-2'], findingIds: ['f-009'] },
    { id: 'n-4', framework: 'nist', controlId: 'CM-6', title: 'Configuration Settings', description: 'Establish configuration settings for IT products used within the information system.', status: 'partial', evidence: ['Container running as root', 'SSH unrestricted'], findingIds: ['f-011', 'f-006'] },
    { id: 'n-5', framework: 'nist', controlId: 'SC-8', title: 'Transmission Confidentiality & Integrity', description: 'Implement cryptographic mechanisms to prevent unauthorized disclosure of information.', status: 'partial', evidence: ['HTTP not redirected to HTTPS'], findingIds: ['f-013'] },
    { id: 'n-6', framework: 'nist', controlId: 'SI-2', title: 'Flaw Remediation', description: 'Identify, report, and correct information system flaws.', status: 'fail', evidence: ['Critical CVEs unpatched: CVE-2024-21626, CVE-2024-3094'], findingIds: ['f-001', 'f-002'] },
    { id: 'n-7', framework: 'nist', controlId: 'IR-4', title: 'Incident Handling', description: 'Implement incident handling capability including preparation, detection, and recovery.', status: 'pass', evidence: ['Incident response playbooks documented', 'On-call rotation active'], findingIds: [] },
    { id: 'n-8', framework: 'nist', controlId: 'RA-5', title: 'Vulnerability Scanning', description: 'Scan for vulnerabilities in the information system and hosted applications.', status: 'pass', evidence: ['CloudShield scanning pipeline active', 'Last scan: 2024-02-23'], findingIds: [] },

    // ISO
    { id: 'i-1', framework: 'iso', controlId: 'A.9.4.1', title: 'Information Access Restriction', description: 'Access to information and application system functions shall be restricted.', status: 'fail', evidence: ['S3 bucket publicly accessible'], findingIds: ['f-003'] },
    { id: 'i-2', framework: 'iso', controlId: 'A.10.1.1', title: 'Policy on Use of Cryptographic Controls', description: 'Policy on the use of cryptographic controls for protection of information.', status: 'fail', evidence: ['RDS unencrypted', 'HTTP not enforced'], findingIds: ['f-008', 'f-013'] },
    { id: 'i-3', framework: 'iso', controlId: 'A.12.6.1', title: 'Management of Technical Vulnerabilities', description: 'Timely identification of technical vulnerabilities.', status: 'partial', evidence: ['Scanning active but critical CVEs open >48h'], findingIds: ['f-001', 'f-002'] },
    { id: 'i-4', framework: 'iso', controlId: 'A.13.1.1', title: 'Network Controls', description: 'Networks shall be managed and controlled to protect information in systems.', status: 'fail', evidence: ['SSH open to 0.0.0.0/0', 'EKS public endpoint'], findingIds: ['f-006', 'f-014'] },
    { id: 'i-5', framework: 'iso', controlId: 'A.12.4.1', title: 'Event Logging', description: 'Event logs recording user activities shall be produced and kept.', status: 'fail', evidence: ['CloudTrail disabled in us-west-2'], findingIds: ['f-009'] },
    { id: 'i-6', framework: 'iso', controlId: 'A.9.2.3', title: 'Management of Privileged Access Rights', description: 'Allocation and use of privileged access rights shall be restricted and controlled.', status: 'fail', evidence: ['IAM wildcard role', '14 users without MFA'], findingIds: ['f-004', 'f-012'] },
];

// ─── Compliance Summary ──────────────────────────────────────────────────────

export const complianceSummary = {
    hipaa: { pass: 2, fail: 2, partial: 2, total: 6, percentage: 70 },
    nist: { pass: 2, fail: 3, partial: 3, total: 8, percentage: 75 },
    iso: { pass: 0, fail: 5, partial: 1, total: 6, percentage: 48 },
};

// ─── AI Chat Mock Responses ─────────────────────────────────────────────────

export const aiResponses: Record<string, string[]> = {
    default: [
        "I've analyzed the finding and can provide remediation guidance. Based on the severity and context, here's what I recommend:",
        "This is a high-priority issue that requires immediate attention. Let me walk you through the remediation steps:",
        "I've cross-referenced this finding with our compliance frameworks. Here's the risk assessment and fix:",
    ],
    greeting: [
        "Hello! I'm CloudShield AI, your security remediation assistant. I can help you understand vulnerabilities, generate remediation commands, and assess compliance impact. Select a finding on the left to get started!",
    ],
};
