#!/usr/bin/env python3
"""Run the same scenarios against the AWS Emulator or real AWS and record
normalized results per step.

    python3 fidelity.py emu   -> results-emu.json   (needs the emulator running)
    python3 fidelity.py aws   -> results-aws.json   (creates cheap resources, then deletes them)

Every resource name starts with a per-run prefix. The AWS run cleans up in a
finally block and records whether cleanup worked.
"""
import base64, io, json, os, re, sys, time, uuid, zipfile, datetime
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

BACKEND = sys.argv[1]
assert BACKEND in ("emu", "aws")
RUN = "emufid" + uuid.uuid4().hex[:6]
REGION = "us-east-1"
HOME = os.path.expanduser("~")

if BACKEND == "emu":
    d = f"{HOME}/.aws/emulator/9297"
    os.environ.update({
        "AWS_ENDPOINT_URL": "https://127.0.0.1:9297",
        "AWS_SHARED_CREDENTIALS_FILE": f"{d}/emulator_credentials",
        "AWS_CONFIG_FILE": f"{d}/config",
        "AWS_CA_BUNDLE": f"{d}/ca.pem",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_DISABLE_HOST_PREFIX_INJECTION": "true",
    })
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        os.environ.pop(k, None)

cfg = Config(region_name=REGION, retries={"max_attempts": 1}, read_timeout=60)
sess = boto3.Session(region_name=REGION)
def cl(name): return sess.client(name, config=cfg)

sts = cl("sts")
ACCOUNT = sts.get_caller_identity()["Account"]
if BACKEND == "emu":
    assert ACCOUNT == "000000000000", "not talking to the emulator"
else:
    assert ACCOUNT != "000000000000"
print(f"backend={BACKEND} account={ACCOUNT} run={RUN}", flush=True)

s3, ddb, sqs, kms, iam, lam, evb = (cl(x) for x in ("s3", "dynamodb", "sqs", "kms", "iam", "lambda", "events"))

RESULTS = []
def norm(o):
    """Strip values that legitimately differ between runs/backends."""
    if isinstance(o, dict):
        return {k: norm(v) for k, v in o.items() if k not in ("ResponseMetadata",)}
    if isinstance(o, list):
        return [norm(v) for v in o]
    if isinstance(o, (datetime.datetime, datetime.date)):
        return "<ts>"
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    if isinstance(o, str):
        s = o.replace(ACCOUNT, "<acct>").replace(RUN, "<run>")
        s = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", s)
        s = re.sub(r"\b[0-9a-f]{32,}\b", "<hex>", s)
        s = re.sub(r"(?<=request id: )\S+", "<rid>", s)
        return s
    return o

def step(group, name, fn, project=None):
    rec = {"group": group, "step": name}
    t0 = time.time()
    try:
        res = fn()
        rec["ok"] = True
        if isinstance(res, dict) and "ResponseMetadata" in res:
            rec["status"] = res.get("ResponseMetadata", {}).get("HTTPStatusCode")
            rec["keys"] = sorted(k for k in res if k != "ResponseMetadata")
            if project:
                rec["val"] = norm(project(res))
        elif isinstance(res, dict):
            rec["val"] = norm(res)
        elif res is not None:
            rec["val"] = norm(res)
    except ClientError as e:
        rec["ok"] = False
        err = e.response.get("Error", {})
        rec["code"] = err.get("Code")
        rec["status"] = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        rec["msg"] = norm(err.get("Message", ""))
        extra = {k: v for k, v in e.response.items() if k not in ("Error", "ResponseMetadata", "message")}
        if extra:
            rec["extra"] = norm(extra)
    except Exception as e:  # client-side validation, connection errors, bugs
        rec["ok"] = False
        rec["code"] = "CLIENT:" + type(e).__name__
        rec["msg"] = norm(str(e))[:300]
    rec["secs"] = round(time.time() - t0, 2)
    RESULTS.append(rec)
    flag = "ok " if rec["ok"] else "ERR"
    print(f"  [{flag}] {group}/{name} {rec.get('code','')}", flush=True)
    return rec

N = lambda x: f"{RUN}-{x}"
S = {}  # shared state between steps

# ---------------------------------------------------------------- KMS
def kms_group():
    g = "kms"
    r = step(g, "create_key", lambda: kms.create_key(Description=N("key")),
             lambda r: {k: r["KeyMetadata"].get(k) for k in ("KeyState", "KeyUsage", "KeySpec", "Origin", "Enabled", "MultiRegion", "KeyManager", "EncryptionAlgorithms")})
    S["key_id"] = None
    try:
        S["key_id"] = kms.list_keys()["Keys"][-1]["KeyId"]
    except Exception: pass
    # use the key we just created, not a guess
    def mk():
        resp = kms.create_key(Description=N("key2"))
        S["key_id"] = resp["KeyMetadata"]["KeyId"]
        return resp
    step(g, "create_key_for_tests", mk, lambda r: {"KeyState": r["KeyMetadata"]["KeyState"]})
    kid = S["key_id"]
    S.setdefault("keys", []).append(kid)
    step(g, "describe_key", lambda: kms.describe_key(KeyId=kid),
         lambda r: {k: r["KeyMetadata"].get(k) for k in ("KeyState", "KeyUsage", "KeySpec", "Origin", "Enabled", "KeyManager")})
    ctx = {"purpose": "fid"}
    step(g, "encrypt", lambda: S.__setitem__("ct", kms.encrypt(KeyId=kid, Plaintext=b"hello", EncryptionContext=ctx)["CiphertextBlob"]) or {"ok": 1})
    step(g, "decrypt_roundtrip", lambda: kms.decrypt(CiphertextBlob=S["ct"], EncryptionContext=ctx),
         lambda r: {"Plaintext": r["Plaintext"], "EncryptionAlgorithm": r.get("EncryptionAlgorithm")})
    step(g, "decrypt_wrong_context", lambda: kms.decrypt(CiphertextBlob=S["ct"], EncryptionContext={"purpose": "other"}))
    step(g, "decrypt_garbage", lambda: kms.decrypt(CiphertextBlob=b"not-a-ciphertext"))
    step(g, "encrypt_too_large", lambda: kms.encrypt(KeyId=kid, Plaintext=b"x" * 5000))
    step(g, "encrypt_missing_key", lambda: kms.encrypt(KeyId="1234abcd-12ab-34cd-56ef-1234567890ab", Plaintext=b"x"))
    step(g, "generate_data_key", lambda: kms.generate_data_key(KeyId=kid, KeySpec="AES_256"),
         lambda r: {"plain_len": len(r["Plaintext"]), "has_blob": bool(r["CiphertextBlob"])})
    step(g, "create_alias_invalid_name", lambda: kms.create_alias(AliasName="no-prefix", TargetKeyId=kid))
    step(g, "create_alias", lambda: kms.create_alias(AliasName=f"alias/{N('a')}", TargetKeyId=kid))
    step(g, "create_alias_duplicate", lambda: kms.create_alias(AliasName=f"alias/{N('a')}", TargetKeyId=kid))
    step(g, "disable_key", lambda: kms.disable_key(KeyId=kid))
    step(g, "encrypt_with_disabled_key", lambda: kms.encrypt(KeyId=kid, Plaintext=b"x"))
    step(g, "enable_key", lambda: kms.enable_key(KeyId=kid))
    step(g, "schedule_deletion_window_too_short", lambda: kms.schedule_key_deletion(KeyId=kid, PendingWindowInDays=3))

# ---------------------------------------------------------------- S3
def s3_group():
    g = "s3"
    b = N("bkt")
    S["bucket"] = b
    step(g, "create_bucket", lambda: s3.create_bucket(Bucket=b), lambda r: {"Location": r.get("Location")})
    step(g, "create_bucket_again_same_owner", lambda: s3.create_bucket(Bucket=b))
    step(g, "create_bucket_invalid_name", lambda: s3.create_bucket(Bucket="Bad_Name"))
    step(g, "put_object", lambda: s3.put_object(Bucket=b, Key="a/one.txt", Body=b"hello world"), lambda r: {"ETag": r["ETag"]})
    step(g, "get_object", lambda: s3.get_object(Bucket=b, Key="a/one.txt"),
         lambda r: {"body": r["Body"].read(), "ETag": r["ETag"], "ContentLength": r["ContentLength"], "ContentType": r["ContentType"]})
    step(g, "get_object_range", lambda: s3.get_object(Bucket=b, Key="a/one.txt", Range="bytes=0-4"),
         lambda r: {"body": r["Body"].read(), "ContentRange": r.get("ContentRange")})
    step(g, "get_object_missing", lambda: s3.get_object(Bucket=b, Key="nope"))
    step(g, "head_object_missing", lambda: s3.head_object(Bucket=b, Key="nope"))
    step(g, "get_object_missing_bucket", lambda: s3.get_object(Bucket=N("nobucket"), Key="x"))
    step(g, "put_object_if_none_match_first", lambda: s3.put_object(Bucket=b, Key="cond.txt", Body=b"1", IfNoneMatch="*"))
    step(g, "put_object_if_none_match_second", lambda: s3.put_object(Bucket=b, Key="cond.txt", Body=b"2", IfNoneMatch="*"))
    for k in ("a/two.txt", "b/three.txt", "top.txt"):
        s3.put_object(Bucket=b, Key=k, Body=b"x")
    step(g, "list_objects_v2_delimiter", lambda: s3.list_objects_v2(Bucket=b, Delimiter="/"),
         lambda r: {"prefixes": [p["Prefix"] for p in r.get("CommonPrefixes", [])], "keys": [c["Key"] for c in r.get("Contents", [])], "KeyCount": r["KeyCount"]})
    step(g, "list_objects_v2_prefix_maxkeys", lambda: s3.list_objects_v2(Bucket=b, Prefix="a/", MaxKeys=1),
         lambda r: {"keys": [c["Key"] for c in r.get("Contents", [])], "IsTruncated": r["IsTruncated"], "has_token": "NextContinuationToken" in r})
    step(g, "copy_object", lambda: s3.copy_object(Bucket=b, Key="a/copy.txt", CopySource={"Bucket": b, "Key": "a/one.txt"}),
         lambda r: {"ETag": r["CopyObjectResult"]["ETag"]})
    step(g, "delete_objects_with_missing_key", lambda: s3.delete_objects(Bucket=b, Delete={"Objects": [{"Key": "top.txt"}, {"Key": "never-existed"}]}),
         lambda r: {"deleted": sorted(d["Key"] for d in r.get("Deleted", [])), "errors": r.get("Errors", [])})
    step(g, "delete_nonempty_bucket", lambda: s3.delete_bucket(Bucket=b))
    # KMS-encrypted put, the autopilot-demo path
    kid = S.get("key_id")
    if kid:
        step(g, "put_object_sse_kms", lambda: s3.put_object(Bucket=b, Key="kms.txt", Body=b"secret", ServerSideEncryption="aws:kms", SSEKMSKeyId=kid),
             lambda r: {"SSE": r.get("ServerSideEncryption"), "key_matches": kid in (r.get("SSEKMSKeyId") or "")})
        step(g, "get_object_sse_kms", lambda: s3.get_object(Bucket=b, Key="kms.txt"),
             lambda r: {"body": r["Body"].read(), "SSE": r.get("ServerSideEncryption")})
    step(g, "put_object_sse_kms_missing_key", lambda: s3.put_object(Bucket=b, Key="kms2.txt", Body=b"s", ServerSideEncryption="aws:kms",
                                                                    SSEKMSKeyId="1234abcd-12ab-34cd-56ef-1234567890ab"))
    # versioning
    step(g, "put_bucket_versioning", lambda: s3.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"}))
    s3.put_object(Bucket=b, Key="v.txt", Body=b"1"); s3.put_object(Bucket=b, Key="v.txt", Body=b"2")
    step(g, "list_object_versions_count", lambda: s3.list_object_versions(Bucket=b, Prefix="v.txt"),
         lambda r: {"versions": len(r.get("Versions", [])), "latest_flags": [v["IsLatest"] for v in r.get("Versions", [])]})
    step(g, "delete_object_versioned_marker", lambda: s3.delete_object(Bucket=b, Key="v.txt"),
         lambda r: {"DeleteMarker": r.get("DeleteMarker"), "has_version_id": "VersionId" in r})
    step(g, "get_object_after_delete_marker", lambda: s3.get_object(Bucket=b, Key="v.txt"))

# ---------------------------------------------------------------- DynamoDB
def ddb_group():
    g = "dynamodb"
    t = N("tbl")
    S["table"] = t
    step(g, "create_table", lambda: ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "N"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}]),
        lambda r: {"TableStatus": r["TableDescription"]["TableStatus"], "KeySchema": r["TableDescription"]["KeySchema"]})
    step(g, "create_table_duplicate", lambda: ddb.create_table(TableName=t, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}], KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}]))
    step(g, "wait_active", lambda: ddb.get_waiter("table_exists").wait(TableName=t) or {"waited": True})
    step(g, "describe_table", lambda: ddb.describe_table(TableName=t),
         lambda r: {k: r["Table"].get(k) for k in ("TableStatus", "BillingModeSummary", "ItemCount", "KeySchema", "AttributeDefinitions")})
    item = lambda sk, **kw: {"pk": {"S": "u1"}, "sk": {"N": str(sk)}, **kw}
    step(g, "put_item", lambda: ddb.put_item(TableName=t, Item=item(1, name={"S": "ann"}, n={"N": "1.50"})))
    step(g, "get_item", lambda: ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "1"}}), lambda r: r.get("Item"))
    step(g, "get_item_missing", lambda: ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "99"}}), lambda r: {"has_item": "Item" in r})
    step(g, "put_item_condition_fails", lambda: ddb.put_item(TableName=t, Item=item(1, name={"S": "bob"}),
        ConditionExpression="attribute_not_exists(pk)", ReturnValuesOnConditionCheckFailure="ALL_OLD"))
    step(g, "put_item_wrong_key_type", lambda: ddb.put_item(TableName=t, Item={"pk": {"N": "1"}, "sk": {"N": "1"}}))
    step(g, "put_item_empty_string_key", lambda: ddb.put_item(TableName=t, Item={"pk": {"S": ""}, "sk": {"N": "1"}}))
    step(g, "put_item_missing_sort_key", lambda: ddb.put_item(TableName=t, Item={"pk": {"S": "u1"}}))
    step(g, "put_item_over_400kb", lambda: ddb.put_item(TableName=t, Item=item(2, big={"S": "x" * 410_000})))
    step(g, "update_item_add_return_new", lambda: ddb.update_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "1"}},
        UpdateExpression="SET hits = if_not_exists(hits, :z) + :one", ExpressionAttributeValues={":z": {"N": "0"}, ":one": {"N": "1"}},
        ReturnValues="ALL_NEW"), lambda r: r["Attributes"])
    step(g, "update_item_reserved_word_no_alias", lambda: ddb.update_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "1"}},
        UpdateExpression="SET name = :v", ExpressionAttributeValues={":v": {"S": "z"}}))
    for i in range(2, 6):
        ddb.put_item(TableName=t, Item=item(i, tag={"S": "even" if i % 2 == 0 else "odd"}))
    step(g, "query_range", lambda: ddb.query(TableName=t, KeyConditionExpression="pk = :p AND sk BETWEEN :a AND :b",
        ExpressionAttributeValues={":p": {"S": "u1"}, ":a": {"N": "2"}, ":b": {"N": "4"}}),
        lambda r: {"sks": [i["sk"]["N"] for i in r["Items"]], "Count": r["Count"], "ScannedCount": r["ScannedCount"]})
    step(g, "query_limit_pagination", lambda: ddb.query(TableName=t, KeyConditionExpression="pk = :p", Limit=2, ScanIndexForward=False,
        ExpressionAttributeValues={":p": {"S": "u1"}}),
        lambda r: {"sks": [i["sk"]["N"] for i in r["Items"]], "LastEvaluatedKey": r.get("LastEvaluatedKey")})
    step(g, "scan_filter", lambda: ddb.scan(TableName=t, FilterExpression="tag = :t", ExpressionAttributeValues={":t": {"S": "even"}}),
        lambda r: {"Count": r["Count"], "ScannedCount": r["ScannedCount"]})
    step(g, "query_without_partition_key", lambda: ddb.query(TableName=t, KeyConditionExpression="sk = :a", ExpressionAttributeValues={":a": {"N": "2"}}))
    step(g, "batch_write_26_items", lambda: ddb.batch_write_item(RequestItems={t: [{"PutRequest": {"Item": item(100 + i)}} for i in range(26)]}))
    step(g, "transact_write_condition_fails", lambda: ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": t, "Item": item(200)}},
        {"Put": {"TableName": t, "Item": item(1), "ConditionExpression": "attribute_not_exists(pk)"}}]))
    step(g, "transact_write_item_not_applied", lambda: ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "200"}}), lambda r: {"has_item": "Item" in r})
    step(g, "number_precision_roundtrip", lambda: (ddb.put_item(TableName=t, Item=item(300, n={"N": "3.14159265358979323846264338327950288"})),
        ddb.get_item(TableName=t, Key={"pk": {"S": "u1"}, "sk": {"N": "300"}}))[1], lambda r: r["Item"]["n"])
    step(g, "delete_table", lambda: ddb.delete_table(TableName=t), lambda r: {"TableStatus": r["TableDescription"]["TableStatus"]})
    step(g, "describe_deleted_table", lambda: (ddb.get_waiter("table_not_exists").wait(TableName=t), ddb.describe_table(TableName=t))[1])

# ---------------------------------------------------------------- SQS
def sqs_group():
    g = "sqs"
    q = N("q")
    r = step(g, "create_queue", lambda: sqs.create_queue(QueueName=q), lambda r: {"url_tail": r["QueueUrl"].split("/")[-1]})
    S["qurl"] = sqs.get_queue_url(QueueName=q)["QueueUrl"]
    qu = S["qurl"]
    step(g, "create_queue_different_attrs_same_name", lambda: sqs.create_queue(QueueName=q, Attributes={"VisibilityTimeout": "99"}))
    step(g, "send_message", lambda: sqs.send_message(QueueUrl=qu, MessageBody="hi"), lambda r: {"md5": r["MD5OfMessageBody"]})
    step(g, "receive_message", lambda: sqs.receive_message(QueueUrl=qu, MaxNumberOfMessages=1, AttributeNames=["All"]),
         lambda r: {"body": r["Messages"][0]["Body"], "receive_count": r["Messages"][0]["Attributes"]["ApproximateReceiveCount"],
                    "attr_names": sorted(r["Messages"][0]["Attributes"])} if r.get("Messages") else {"empty": True})
    step(g, "receive_again_during_visibility_timeout", lambda: sqs.receive_message(QueueUrl=qu), lambda r: {"empty": not r.get("Messages")})
    step(g, "delete_message_bad_receipt_handle", lambda: sqs.delete_message(QueueUrl=qu, ReceiptHandle="garbage"))
    step(g, "send_message_too_large", lambda: sqs.send_message(QueueUrl=qu, MessageBody="x" * 262_145))
    step(g, "send_message_invalid_char", lambda: sqs.send_message(QueueUrl=qu, MessageBody="bad\x00char"))
    step(g, "send_batch_11_entries", lambda: sqs.send_message_batch(QueueUrl=qu, Entries=[{"Id": str(i), "MessageBody": "m"} for i in range(11)]))
    step(g, "send_batch_duplicate_ids", lambda: sqs.send_message_batch(QueueUrl=qu, Entries=[{"Id": "1", "MessageBody": "m"}, {"Id": "1", "MessageBody": "n"}]))
    step(g, "get_queue_attributes_all", lambda: sqs.get_queue_attributes(QueueUrl=qu, AttributeNames=["All"]),
         lambda r: {"names": sorted(r["Attributes"]), "VisibilityTimeout": r["Attributes"].get("VisibilityTimeout"),
                    "MaximumMessageSize": r["Attributes"].get("MaximumMessageSize")})
    step(g, "get_queue_url_missing", lambda: sqs.get_queue_url(QueueName=N("nope")))
    # FIFO
    fq = N("f") + ".fifo"
    step(g, "create_fifo_queue", lambda: sqs.create_queue(QueueName=fq, Attributes={"FifoQueue": "true"}), lambda r: {"ends_fifo": r["QueueUrl"].endswith(".fifo")})
    fu = sqs.get_queue_url(QueueName=fq)["QueueUrl"]; S["fifo"] = fu
    step(g, "create_fifo_without_suffix", lambda: sqs.create_queue(QueueName=N("nofifo"), Attributes={"FifoQueue": "true"}))
    step(g, "fifo_send_without_group_id", lambda: sqs.send_message(QueueUrl=fu, MessageBody="x", MessageDeduplicationId="d1"))
    step(g, "fifo_send_without_dedup_id", lambda: sqs.send_message(QueueUrl=fu, MessageBody="x", MessageGroupId="g"))
    ids = []
    def send_dup():
        a = sqs.send_message(QueueUrl=fu, MessageBody="dup", MessageGroupId="g", MessageDeduplicationId="same")
        b = sqs.send_message(QueueUrl=fu, MessageBody="dup", MessageGroupId="g", MessageDeduplicationId="same")
        return {"same_message_id": a["MessageId"] == b["MessageId"], "has_seq": "SequenceNumber" in a}
    step(g, "fifo_dedup_same_message_id", send_dup)
    step(g, "fifo_receive_count_after_dedup", lambda: sqs.receive_message(QueueUrl=fu, MaxNumberOfMessages=10, WaitTimeSeconds=1),
         lambda r: {"n": len(r.get("Messages", []))})
    step(g, "purge_queue", lambda: sqs.purge_queue(QueueUrl=qu))
    step(g, "purge_queue_again_immediately", lambda: sqs.purge_queue(QueueUrl=qu))

# ---------------------------------------------------------------- IAM
TRUST_LAMBDA = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
def iam_group():
    g = "iam"
    r = N("role")
    S["role"] = r
    step(g, "create_role", lambda: iam.create_role(RoleName=r, AssumeRolePolicyDocument=TRUST_LAMBDA),
         lambda x: {"Path": x["Role"]["Path"], "arn_tail": x["Role"]["Arn"].split(":", 5)[-1]})
    step(g, "create_role_duplicate", lambda: iam.create_role(RoleName=r, AssumeRolePolicyDocument=TRUST_LAMBDA))
    step(g, "create_role_malformed_trust", lambda: iam.create_role(RoleName=N("bad"), AssumeRolePolicyDocument="{not json"))
    step(g, "create_role_trust_without_principal", lambda: iam.create_role(RoleName=N("bad2"),
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole"}]})))
    step(g, "get_role", lambda: iam.get_role(RoleName=r), lambda x: {"trust": x["Role"]["AssumeRolePolicyDocument"], "MaxSessionDuration": x["Role"].get("MaxSessionDuration")})
    step(g, "put_role_policy", lambda: iam.put_role_policy(RoleName=r, PolicyName="p", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})))
    step(g, "put_role_policy_invalid_action_format", lambda: iam.put_role_policy(RoleName=r, PolicyName="p2", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "not-an-action", "Resource": "*"}]})))
    step(g, "put_role_policy_missing_resource", lambda: iam.put_role_policy(RoleName=r, PolicyName="p3", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]})))
    step(g, "attach_nonexistent_managed_policy", lambda: iam.attach_role_policy(RoleName=r, PolicyArn="arn:aws:iam::aws:policy/DoesNotExist"))
    step(g, "get_role_missing", lambda: iam.get_role(RoleName=N("missing")))
    step(g, "delete_role_with_inline_policy", lambda: iam.delete_role(RoleName=r))
    step(g, "simulate_principal_policy", lambda: iam.simulate_principal_policy(
        PolicySourceArn=iam.get_role(RoleName=r)["Role"]["Arn"], ActionNames=["s3:GetObject", "s3:PutObject"], ResourceArns=["*"]),
        lambda x: {a["EvalActionName"]: a["EvalDecision"] for a in x["EvaluationResults"]})

# ---------------------------------------------------------------- IAM enforcement (test C)
def enforcement_group():
    """Create a role with a narrow policy and call S3/DynamoDB as that role.
    Real AWS must deny what the policy does not allow."""
    g = "iam_enforcement"
    r = N("limited")
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]})
    iam.create_role(RoleName=r, AssumeRolePolicyDocument=trust)
    S["limited_role"] = r
    b = S["bucket"]
    iam.put_role_policy(RoleName=r, PolicyName="narrow", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{b}/a/*"}]}))
    time.sleep(12 if BACKEND == "aws" else 1)  # IAM propagation on real AWS
    arn = f"arn:aws:iam::{ACCOUNT}:role/{r}"
    creds = None
    for attempt in range(6):
        try:
            creds = sts.assume_role(RoleArn=arn, RoleSessionName="fid")["Credentials"]; break
        except ClientError:
            time.sleep(5)
    step(g, "assume_role", lambda: {"got_creds": creds is not None})
    if not creds:
        return
    s3r = sess.client("s3", config=cfg, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"])
    step(g, "allowed_get_object_in_prefix", lambda: s3r.get_object(Bucket=b, Key="a/one.txt"), lambda x: {"body": x["Body"].read()})
    step(g, "denied_get_object_outside_prefix", lambda: s3r.get_object(Bucket=b, Key="b/three.txt"))
    step(g, "denied_put_object", lambda: s3r.put_object(Bucket=b, Key="a/new.txt", Body=b"x"))
    step(g, "denied_list_bucket", lambda: s3r.list_objects_v2(Bucket=b))
    step(g, "denied_delete_object", lambda: s3r.delete_object(Bucket=b, Key="a/one.txt"))
    # The autopilot-demo trap: a policy with s3:PutObject but not kms:GenerateDataKey
    kid = S.get("key_id")
    if kid:
        iam.put_role_policy(RoleName=r, PolicyName="s3put_only", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{b}/*"}]}))
        time.sleep(10 if BACKEND == "aws" else 1)
        step(g, "autopilot_trap_put_sse_kms_without_kms_permission", lambda: s3r.put_object(
            Bucket=b, Key="trap.txt", Body=b"x", ServerSideEncryption="aws:kms", SSEKMSKeyId=kid))


# ---------------------------------------------------------------- IAM enforcement, harder cases
def enforcement2_group():
    """Where does policy evaluation stop? Each case is allowed or denied on real AWS."""
    g = "iam_enforcement2"
    b = S["bucket"]
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "sts:AssumeRole"}]})
    pol = lambda *st: json.dumps({"Version": "2012-10-17", "Statement": list(st)})
    allow = lambda act, res: {"Effect": "Allow", "Action": act, "Resource": res}
    for k in ("secret/x", "bp/x", "a/one.txt", "b/three.txt"):
        s3.put_object(Bucket=b, Key=k, Body=b"data")
    roles = {}
    def mk(tag, policy=None, boundary=None):
        rn = N("e2" + tag); S.setdefault("extra_roles", []).append(rn)
        iam.create_role(RoleName=rn, AssumeRolePolicyDocument=trust)
        if policy: iam.put_role_policy(RoleName=rn, PolicyName="p", PolicyDocument=policy)
        if boundary: iam.put_role_permissions_boundary(RoleName=rn, PermissionsBoundary=boundary)
        roles[tag] = rn
    B = f"arn:aws:s3:::{b}"
    mk("nopol")
    mk("deny", pol(allow("s3:*", [B, B + "/*"]), {"Effect": "Deny", "Action": "s3:GetObject", "Resource": B + "/secret/*"}))
    mk("bp", pol(allow("s3:*", [B, B + "/*"])))
    mk("cond", pol({"Effect": "Allow", "Action": "s3:ListBucket", "Resource": B, "Condition": {"StringLike": {"s3:prefix": ["a/*"]}}}))
    bnd = iam.create_policy(PolicyName=N("bnd"), PolicyDocument=pol(allow("s3:GetObject", B + "/*")))["Policy"]["Arn"]
    S["bnd_policy"] = bnd
    mk("bnd", pol(allow("s3:*", [B, B + "/*"])), boundary=bnd)
    mk("sess", pol(allow("s3:*", [B, B + "/*"])))
    bp = pol({"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/{roles['bp']}"},
              "Action": "s3:GetObject", "Resource": B + "/bp/*"})
    # First attempt, seconds after the role was created: real AWS may not resolve the principal yet.
    first = step(g, "put_bucket_policy_principal_created_seconds_ago", lambda: s3.put_bucket_policy(Bucket=b, Policy=bp))
    for _ in range(10):
        if first["ok"]: break
        time.sleep(6)
        try: s3.put_bucket_policy(Bucket=b, Policy=bp); first["ok"] = True
        except ClientError: pass
    time.sleep(15 if BACKEND == "aws" else 1)
    def client_for(tag, session_policy=None):
        arn = f"arn:aws:iam::{ACCOUNT}:role/{roles[tag]}"
        for _ in range(8):
            try:
                kw = {"Policy": session_policy} if session_policy else {}
                c = sts.assume_role(RoleArn=arn, RoleSessionName="fid2", **kw)["Credentials"]
                return sess.client("s3", config=cfg, aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
            except ClientError:
                time.sleep(5)
    get = lambda c, k: (lambda: c.get_object(Bucket=b, Key=k)["Body"].read())
    c = client_for("nopol")
    step(g, "role_with_no_policy_get", get(c, "a/one.txt"))
    c = client_for("deny")
    step(g, "explicit_deny_prefix_denied", get(c, "secret/x"))
    step(g, "explicit_deny_other_prefix_allowed", get(c, "a/one.txt"))
    c = client_for("bp")
    step(g, "bucket_policy_deny_denied", get(c, "bp/x"))
    step(g, "bucket_policy_deny_other_allowed", get(c, "a/one.txt"))
    c = client_for("cond")
    step(g, "condition_list_allowed_prefix", lambda: c.list_objects_v2(Bucket=b, Prefix="a/"), lambda r: {"KeyCount": r["KeyCount"]})
    step(g, "condition_list_other_prefix", lambda: c.list_objects_v2(Bucket=b, Prefix="b/"))
    step(g, "condition_list_no_prefix", lambda: c.list_objects_v2(Bucket=b))
    c = client_for("bnd")
    step(g, "permissions_boundary_get_allowed", get(c, "a/one.txt"))
    step(g, "permissions_boundary_put_denied", lambda: c.put_object(Bucket=b, Key="a/bnd.txt", Body=b"x"))
    c = client_for("sess", session_policy=pol(allow("s3:GetObject", B + "/*")))
    step(g, "session_policy_get_allowed", get(c, "a/one.txt"))
    step(g, "session_policy_put_denied", lambda: c.put_object(Bucket=b, Key="a/sess.txt", Body=b"x"))

# ---------------------------------------------------------------- Lambda
def zip_py(code):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", code)
    return buf.getvalue()

OK_CODE = "import os\ndef handler(event, context):\n    return {'echo': event, 'env': os.environ.get('GREETING'), 'fn': context.function_name}\n"
ERR_CODE = "def handler(event, context):\n    raise ValueError('boom')\n"

def lambda_group():
    g = "lambda"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{S['role']}"
    if BACKEND == "aws":
        time.sleep(10)  # let the role propagate
    fn = N("fn")
    S["fn"] = fn
    for attempt in range(4):
        rec = step(g, "create_function" if attempt == 0 else f"create_function_retry{attempt}", lambda: lam.create_function(
            FunctionName=fn, Runtime="python3.13", Role=role_arn, Handler="index.handler", Code={"ZipFile": zip_py(OK_CODE)},
            Environment={"Variables": {"GREETING": "hi"}}, Timeout=10, MemorySize=128),
            lambda r: {k: r.get(k) for k in ("Runtime", "Handler", "MemorySize", "Timeout", "PackageType", "State", "Architectures")})
        if rec["ok"] or "cannot be assumed" not in rec.get("msg", ""):
            break
        time.sleep(8)
    step(g, "create_function_duplicate", lambda: lam.create_function(FunctionName=fn, Runtime="python3.13", Role=role_arn, Handler="index.handler", Code={"ZipFile": zip_py(OK_CODE)}))
    step(g, "create_function_bad_runtime", lambda: lam.create_function(FunctionName=N("badrt"), Runtime="python2.0", Role=role_arn, Handler="index.handler", Code={"ZipFile": zip_py(OK_CODE)}))
    step(g, "create_function_role_missing", lambda: lam.create_function(FunctionName=N("norole"), Runtime="python3.13",
        Role=f"arn:aws:iam::{ACCOUNT}:role/{N('doesnotexist')}", Handler="index.handler", Code={"ZipFile": zip_py(OK_CODE)}))
    step(g, "wait_active", lambda: lam.get_waiter("function_active_v2").wait(FunctionName=fn) or {"waited": True})
    step(g, "invoke_ok", lambda: lam.invoke(FunctionName=fn, Payload=json.dumps({"a": 1}).encode()),
         lambda r: {"StatusCode": r["StatusCode"], "FunctionError": r.get("FunctionError"), "payload": json.loads(r["Payload"].read() or b"null")})
    step(g, "invoke_dry_run", lambda: lam.invoke(FunctionName=fn, InvocationType="DryRun"), lambda r: {"StatusCode": r["StatusCode"]})
    step(g, "invoke_event_async", lambda: lam.invoke(FunctionName=fn, InvocationType="Event", Payload=b"{}"), lambda r: {"StatusCode": r["StatusCode"]})
    step(g, "invoke_missing_function", lambda: lam.invoke(FunctionName=N("nofn")))
    step(g, "invoke_bad_json_payload", lambda: lam.invoke(FunctionName=fn, Payload=b"{not json"),
         lambda r: {"StatusCode": r["StatusCode"], "FunctionError": r.get("FunctionError")})
    fe = N("fnerr")
    S["fn_err"] = fe
    lam.create_function(FunctionName=fe, Runtime="python3.13", Role=role_arn, Handler="index.handler", Code={"ZipFile": zip_py(ERR_CODE)}, Timeout=10)
    lam.get_waiter("function_active_v2").wait(FunctionName=fe)
    def inv_err():
        r = lam.invoke(FunctionName=fe, Payload=b"{}")
        body = json.loads(r["Payload"].read())
        return {"StatusCode": r["StatusCode"], "FunctionError": r.get("FunctionError"), "errorType": body.get("errorType"), "errorMessage": body.get("errorMessage")}
    step(g, "invoke_function_raises", inv_err)
    step(g, "update_function_configuration", lambda: lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {"GREETING": "yo"}}),
         lambda r: {"env": r["Environment"]["Variables"]})
    step(g, "invoke_after_env_update", lambda: lam.invoke(FunctionName=fn, Payload=b"{}"), lambda r: {"payload": json.loads(r["Payload"].read())})
    step(g, "get_function", lambda: lam.get_function(FunctionName=fn), lambda r: {"keys": sorted(r["Configuration"])[:40], "code_keys": sorted(r["Code"])})
    step(g, "delete_function", lambda: lam.delete_function(FunctionName=fn))
    step(g, "delete_function_again", lambda: lam.delete_function(FunctionName=fn))

# ---------------------------------------------------------------- EventBridge
def events_group():
    g = "eventbridge"
    bus = N("bus")
    S["bus"] = bus
    step(g, "create_event_bus", lambda: evb.create_event_bus(Name=bus), lambda r: {"arn_tail": r["EventBusArn"].split(":", 5)[-1]})
    step(g, "create_event_bus_duplicate", lambda: evb.create_event_bus(Name=bus))
    pat = json.dumps({"source": ["fid.app"], "detail-type": ["order"], "detail": {"amount": [{"numeric": [">", 100]}]}})
    step(g, "put_rule", lambda: evb.put_rule(Name=N("rule"), EventBusName=bus, EventPattern=pat), lambda r: {"has_arn": "RuleArn" in r})
    step(g, "put_rule_invalid_pattern", lambda: evb.put_rule(Name=N("badrule"), EventBusName=bus, EventPattern='{"source": "not-a-list"}'))
    step(g, "put_rule_schedule_and_pattern", lambda: evb.put_rule(Name=N("both"), EventBusName=bus, EventPattern=pat, ScheduleExpression="rate(5 minutes)"))
    ev = json.dumps({"source": "fid.app", "detail-type": "order", "detail": {"amount": 150}, "id": "1", "account": ACCOUNT, "region": REGION, "time": "2026-01-01T00:00:00Z", "resources": [], "version": "0"})
    step(g, "test_event_pattern_match", lambda: evb.test_event_pattern(EventPattern=pat, Event=ev), lambda r: {"Result": r["Result"]})
    ev2 = ev.replace("150", "50")
    step(g, "test_event_pattern_no_match_numeric", lambda: evb.test_event_pattern(EventPattern=pat, Event=ev2), lambda r: {"Result": r["Result"]})
    step(g, "put_events_to_custom_bus", lambda: evb.put_events(Entries=[{"EventBusName": bus, "Source": "fid.app", "DetailType": "order", "Detail": json.dumps({"amount": 150})}]),
         lambda r: {"FailedEntryCount": r["FailedEntryCount"], "n_entries": len(r["Entries"])})
    step(g, "put_events_bad_detail_json", lambda: evb.put_events(Entries=[{"EventBusName": bus, "Source": "fid.app", "DetailType": "order", "Detail": "{bad"}]),
         lambda r: {"FailedEntryCount": r["FailedEntryCount"], "error_code": r["Entries"][0].get("ErrorCode")})
    step(g, "put_events_missing_source", lambda: evb.put_events(Entries=[{"EventBusName": bus, "DetailType": "order", "Detail": "{}"}]))
    step(g, "put_events_11_entries", lambda: evb.put_events(Entries=[{"EventBusName": bus, "Source": "x", "DetailType": "t", "Detail": "{}"}] * 11))
    # Delivery to SQS. Real AWS needs a queue policy that lets events.amazonaws.com send.
    qname = N("evq")
    qurl = sqs.create_queue(QueueName=qname)["QueueUrl"]; S["evq"] = qurl
    qarn = sqs.get_queue_attributes(QueueUrl=qurl, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    rule = N("deliver")
    evb.put_rule(Name=rule, EventBusName=bus, EventPattern=json.dumps({"source": ["fid.deliver"]}))
    step(g, "put_targets_sqs", lambda: evb.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "q", "Arn": qarn}]), lambda r: {"FailedEntryCount": r["FailedEntryCount"]})
    def send_and_poll(label):
        evb.put_events(Entries=[{"EventBusName": bus, "Source": "fid.deliver", "DetailType": "t", "Detail": json.dumps({"label": label})}])
        deadline = time.time() + (25 if BACKEND == "aws" else 8)
        while time.time() < deadline:
            m = sqs.receive_message(QueueUrl=qurl, WaitTimeSeconds=2).get("Messages", [])
            if m:
                sqs.delete_message(QueueUrl=qurl, ReceiptHandle=m[0]["ReceiptHandle"])
                return {"delivered": True, "detail": json.loads(m[0]["Body"]).get("detail")}
        return {"delivered": False}
    step(g, "delivery_to_sqs_WITHOUT_queue_policy", lambda: send_and_poll("nopolicy"))
    sqs.set_queue_attributes(QueueUrl=qurl, Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": qarn}]})})
    time.sleep(3 if BACKEND == "aws" else 0)
    step(g, "delivery_to_sqs_WITH_queue_policy", lambda: send_and_poll("withpolicy"))

# ---------------------------------------------------------------- cleanup
def cleanup():
    out = {}
    def t(name, fn):
        try: fn(); out[name] = "ok"
        except Exception as e: out[name] = f"{type(e).__name__}: {str(e)[:120]}"
    b = S.get("bucket")
    if b:
        def empty():
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=b):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                if objs: s3.delete_objects(Bucket=b, Delete={"Objects": objs})
            s3.delete_bucket(Bucket=b)
        t("s3_bucket", empty)
    if S.get("table"): t("ddb_table", lambda: ddb.delete_table(TableName=S["table"]))
    for k in ("qurl", "fifo", "evq"):
        if S.get(k): t("sqs_" + k, lambda k=k: sqs.delete_queue(QueueUrl=S[k]))
    for k in ("fn", "fn_err"):
        if S.get(k): t("lambda_" + k, lambda k=k: lam.delete_function(FunctionName=S[k]))
    if S.get("bus"):
        def rm_bus():
            for r in evb.list_rules(EventBusName=S["bus"])["Rules"]:
                tg = evb.list_targets_by_rule(Rule=r["Name"], EventBusName=S["bus"])["Targets"]
                if tg: evb.remove_targets(Rule=r["Name"], EventBusName=S["bus"], Ids=[x["Id"] for x in tg])
                evb.delete_rule(Name=r["Name"], EventBusName=S["bus"])
            evb.delete_event_bus(Name=S["bus"])
        t("events_bus", rm_bus)
    for rn in [S.get("role"), S.get("limited_role")] + S.get("extra_roles", []):
        if rn:
            def rm_role(rn=rn):
                for p in iam.list_role_policies(RoleName=rn)["PolicyNames"]: iam.delete_role_policy(RoleName=rn, PolicyName=p)
                for p in iam.list_attached_role_policies(RoleName=rn)["AttachedPolicies"]:
                    iam.detach_role_policy(RoleName=rn, PolicyArn=p["PolicyArn"])
                try: iam.delete_role_permissions_boundary(RoleName=rn)
                except Exception: pass
                iam.delete_role(RoleName=rn)
            t("iam_" + rn[-8:], rm_role)
    if S.get("bnd_policy"): t("iam_boundary_policy", lambda: iam.delete_policy(PolicyArn=S["bnd_policy"]))
    # KMS: list every key we made via aliases/descriptions
    try:
        for k in kms.list_keys()["Keys"]:
            try: d = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            except Exception: continue
            if RUN in (d.get("Description") or ""):
                if d["KeyState"] == "Disabled": kms.enable_key(KeyId=k["KeyId"])
                try: kms.schedule_key_deletion(KeyId=k["KeyId"], PendingWindowInDays=7); out["kms_" + k["KeyId"][:8]] = "scheduled(7d)"
                except Exception as e: out["kms_" + k["KeyId"][:8]] = f"{type(e).__name__}"
        for a in kms.list_aliases()["Aliases"]:
            if RUN in a["AliasName"]:
                try: kms.delete_alias(AliasName=a["AliasName"])
                except Exception: pass
    except Exception as e:
        out["kms"] = f"{type(e).__name__}: {str(e)[:100]}"
    return out

if __name__ == "__main__":
    groups = [("kms", kms_group), ("s3", s3_group), ("dynamodb", ddb_group), ("sqs", sqs_group),
              ("iam", iam_group), ("iam_enforcement", enforcement_group), ("iam_enforcement2", enforcement2_group), ("lambda", lambda_group), ("eventbridge", events_group)]
    only = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    cleanup_report = {}
    try:
        for name, fn in groups:
            if only and name not in only: continue
            print(f"== {name}", flush=True)
            try:
                fn()
            except Exception as e:
                RESULTS.append({"group": name, "step": "GROUP_ABORTED", "ok": False, "code": "HARNESS:" + type(e).__name__, "msg": norm(str(e))[:300]})
                print(f"  group aborted: {type(e).__name__}: {str(e)[:200]}", flush=True)
    finally:
        cleanup_report = cleanup()
        out = {"backend": BACKEND, "run": RUN, "date": datetime.datetime.now(datetime.timezone.utc).isoformat(), "cleanup": cleanup_report, "results": RESULTS}
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results-{BACKEND}.json")
        json.dump(out, open(path, "w"), indent=1, default=str)
        print("cleanup:", json.dumps(cleanup_report))
        print(f"wrote {path} ({len(RESULTS)} steps)")
