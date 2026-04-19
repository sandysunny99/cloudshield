package cis_docker

import future.keywords.if
import future.keywords.in

# -------------------------------------------------------------------
# CIS Docker Benchmark 5.1: Ensure that the container is not privileged
# -------------------------------------------------------------------
# Running a container in privileged mode allows it to access all devices
# on the host, essentially bypassing the isolation provided by Linux 
# namespaces and cgroups. This check prevents such security regressions.
# -------------------------------------------------------------------
violations[violation] {
    some container in input.containers
    container.privileged == true
    violation := {
        "rule_id": "cis-docker-5.1",
        "severity": "High",
        "description": sprintf("Container %s is running with --privileged flag", [container.name]),
        "remediation": "Remove '--privileged' from the container run command or set 'privileged: false' in docker-compose."
    }
}

# -------------------------------------------------------------------
# CIS Docker Benchmark 5.3: Ensure that containers use read‑only filesystems
# -------------------------------------------------------------------
# A read‑only root filesystem prevents an attacker from modifying or
# writing new files to the filesystem, which is often a prerequisite
# for establishing persistence or exfiltrating data.
# -------------------------------------------------------------------
violations[violation] {
    some container in input.containers
    container.readonly_rootfs == false
    violation := {
        "rule_id": "cis-docker-5.3",
        "severity": "Medium",
        "description": sprintf("Container %s root filesystem is writable", [container.name]),
        "remediation": "Add '--read-only' to the container run command or set 'read_only: true' in docker-compose."
    }
}
