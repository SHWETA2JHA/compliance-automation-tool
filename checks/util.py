def ok(id, title, msg):
    return {"id": id, "title": title, "status": "PASS", "msg": msg}


def bad(id, title, msg):
    return {"id": id, "title": title, "status": "FAIL", "msg": msg}


def warn(id, title, msg):
    return {"id": id, "title": title, "status": "WARN", "msg": msg}
