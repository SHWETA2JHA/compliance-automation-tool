from botocore.exceptions import ClientError

from checks.util import bad, ok


def check_config(session):
    out = []
    cfg = session.client("config", region_name=session.region_name or "us-east-1")

    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError as e:
        out.append(bad("config.on", "Config Off", str(e)))
        return out

    if not recorders:
        out.append(bad("config.on", "Config Off", "No AWS Config recorder."))
        return out

    out.append(ok("config.on", "Config On", "Config recorder exists."))

    status = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if any(s.get("recording") for s in status):
        out.append(ok("config.recording", "Recording", "Config is recording."))
    else:
        out.append(bad("config.recording", "Not Recording", "Start the Config recorder."))

    return out
