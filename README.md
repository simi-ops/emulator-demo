# emulator-demo

Fidelity harness that runs the same 146 API steps against AWS Emulator v1.0.385 and against real AWS, then diffs the results. Real AWS is the answer key.

Write-up: "AWS Emulator vs Real AWS: 146 Steps, 17 Differences".

Result: 129 steps matched, 17 differed.

## Files

| File | Purpose |
|------|---------|
| `fidelity.py` | Runs the scenarios against one backend and writes normalized results |
| `compare.py` | Diffs `results-emu.json` against `results-aws.json` |
| `results-emu.json` | Recorded run against the emulator |
| `results-aws.json` | Recorded run against real AWS (us-east-1, November 15, 2026) |
| `diff.json` | Output of the comparison |
| `env.sh` | Points the CLI and SDK at the local emulator |
| `probe_new_services.sh` | Checks which other services the emulator answers |

## Coverage

S3, DynamoDB, SQS, KMS, IAM (including enforcement with permissions boundaries, session policies, and conditions), Lambda, and EventBridge. Many steps are deliberate failures, since error behavior is where emulators drift.

## Run it

Requires Python 3 and `boto3`.

Against the emulator (start it first, on `https://127.0.0.1:9297`):

```
source env.sh
python3 fidelity.py emu
```

The script refuses to run unless `sts get-caller-identity` returns account `000000000000`. This guards against a missing endpoint variable sending your calls to real AWS.

Against real AWS:

```
python3 fidelity.py aws
```

This uses your default credentials, creates short-lived resources in us-east-1 under a per-run prefix, and deletes them in a `finally` block. It records whether cleanup worked. KMS keys can't be deleted immediately, so they stay in the 7-day deletion window. Expect a few cents of cost.

Run a subset of groups by passing a comma-separated list as the second argument:

```
python3 fidelity.py aws iam_enforcement,iam_enforcement2
```

Compare:

```
python3 compare.py
```

## Notes

- Account IDs, UUIDs, timestamps, and resource names are normalized before comparison, so the recorded results contain placeholders like `<acct>` and `<run>`.
- Run `fidelity.py aws` only in an account you are fine creating test resources in.
