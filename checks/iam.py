import csv
import io

from checks.util import bad, ok, warn


def check_iam(session):
    out = []
    iam = session.client("iam")

    mfa = iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled", 0) == 1
    if mfa:
        out.append(ok("iam.mfa", "MFA Enabled", "Root account has MFA."))
    else:
        out.append(bad("iam.mfa", "MFA Disabled", "Enable MFA on the root account."))

    iam.generate_credential_report()
    rows = list(csv.DictReader(io.StringIO(iam.get_credential_report()["Content"].decode())))
    root = next((r for r in rows if r.get("user") == "<root_account>"), None)
    if root and (root.get("password_last_used") not in ("N/A", "no_information", "") or
                 root.get("access_key_1_active") == "true" or root.get("access_key_2_active") == "true"):
        out.append(bad("iam.root", "Root User Active", "Avoid using the root account."))
    else:
        out.append(ok("iam.root", "Root User Inactive", "Root account looks unused."))

    try:
        iam.get_account_password_policy()
        out.append(ok("iam.password", "Password Policy", "Password policy is set."))
    except iam.exceptions.NoSuchEntityException:
        out.append(bad("iam.password", "No Password Policy", "Add an IAM password policy."))

    return out
