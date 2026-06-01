from checks.util import bad, ok, warn


def open_world(rule):
    for r in rule.get("IpRanges", []):
        if r.get("CidrIp") == "0.0.0.0/0":
            return True
    return False


def check_sgs(session):
    out = []
    ec2 = session.client("ec2")
    groups = ec2.describe_security_groups().get("SecurityGroups", [])

    ssh, rdp, all_ports = [], [], []
    for sg in groups:
        gid = sg["GroupId"]
        for rule in sg.get("IpPermissions", []):
            if not open_world(rule):
                continue
            start = rule.get("FromPort") or 0
            end = rule.get("ToPort") or 65535
            if start == 0 and end == 65535:
                all_ports.append(gid)
            elif start <= 22 <= end:
                ssh.append(gid)
            elif start <= 3389 <= end:
                rdp.append(gid)

    if ssh:
        out.append(warn("sg.ssh", "SSH Open", f"Port 22 open on: {', '.join(list(set(ssh))[:3])}"))
    else:
        out.append(ok("sg.ssh", "SSH Closed", "No public SSH access."))

    if rdp:
        out.append(warn("sg.rdp", "RDP Open", f"Port 3389 open on: {', '.join(list(set(rdp))[:3])}"))
    else:
        out.append(ok("sg.rdp", "RDP Closed", "No public RDP access."))

    if all_ports:
        out.append(bad("sg.all", "All Ports Open", f"Wide open SGs: {', '.join(list(set(all_ports))[:3])}"))
    else:
        out.append(ok("sg.all", "No Wide Open SGs", "No SG allows all ports from internet."))

    return out
