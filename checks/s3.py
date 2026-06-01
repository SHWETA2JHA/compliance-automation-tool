from botocore.exceptions import ClientError

from checks.util import bad, ok, warn


def is_public(s3, name):
    try:
        bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if all(bpa.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            return False
    except ClientError:
        pass
    try:
        for grant in s3.get_bucket_acl(Bucket=name).get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri:
                return True
    except ClientError:
        pass
    return False


def check_s3(session):
    out = []
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        out.append(ok("s3.buckets", "No Buckets", "No S3 buckets in account."))
        return out

    public, no_version, no_encrypt = [], [], []
    for b in buckets:
        name = b["Name"]
        if is_public(s3, name):
            public.append(name)
        try:
            if s3.get_bucket_versioning(Bucket=name).get("Status") != "Enabled":
                no_version.append(name)
        except ClientError:
            no_version.append(name)
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            no_encrypt.append(name)

    if public:
        out.append(bad("s3.public", "Public Buckets", f"Public: {', '.join(public[:3])}"))
    else:
        out.append(ok("s3.public", "No Public Buckets", "Buckets are not public."))

    if no_version:
        out.append(warn("s3.version", "Versioning Off", f"{len(no_version)} bucket(s) without versioning."))
    else:
        out.append(ok("s3.version", "Versioning On", "Versioning enabled on buckets."))

    if no_encrypt:
        out.append(bad("s3.encrypt", "No Encryption", f"{len(no_encrypt)} bucket(s) without encryption."))
    else:
        out.append(ok("s3.encrypt", "Encryption On", "Buckets have default encryption."))

    return out
