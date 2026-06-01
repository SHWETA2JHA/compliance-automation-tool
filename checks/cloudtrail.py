from checks.util import bad, ok, warn


def check_cloudtrail(session):
    out = []
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

    if not trails:
        out.append(bad("cloudtrail.on", "CloudTrail Off", "No trails found."))
        return out

    out.append(ok("cloudtrail.on", "CloudTrail On", f"{len(trails)} trail(s) found."))

    if any(t.get("IsMultiRegionTrail") for t in trails):
        out.append(ok("cloudtrail.multi", "Multi-Region", "Multi-region trail enabled."))
    else:
        out.append(bad("cloudtrail.multi", "Single Region", "Enable multi-region logging."))

    if any(t.get("LogFileValidationEnabled") for t in trails):
        out.append(ok("cloudtrail.validate", "Log Validation", "Log validation is on."))
    else:
        out.append(bad("cloudtrail.validate", "No Log Validation", "Turn on log file validation."))

    logging = [t["Name"] for t in trails if ct.get_trail_status(Name=t["TrailARN"]).get("IsLogging")]
    if logging:
        out.append(ok("cloudtrail.logging", "Logging Active", f"Logging: {', '.join(logging)}"))
    else:
        out.append(warn("cloudtrail.logging", "Not Logging", "Trails exist but logging is off."))

    return out
