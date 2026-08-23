from app.scanner import SAST_RULES, SECRET_RULES


def test_aws_access_key_rule():
    rule = next(r for r in SECRET_RULES if r.id == "aws-access-key")
    assert (
        rule.pattern.search("export AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE") is not None
    )
    assert rule.pattern.search("some text " + "AKIA" + "1234567890123456 here") is not None
    assert rule.pattern.search("invalid AAAAA") is None
    assert rule.severity == "high"


def test_stripe_secret_key_rule():
    rule = next(r for r in SECRET_RULES if r.id == "stripe-secret-key")
    assert (
        rule.pattern.search("STRIPE_KEY = '" + "sk_live_" + "1234567890abcdefghijklmn'") is not None
    )
    assert (
        rule.pattern.search("STRIPE_KEY = '" + "rk_live_" + "1234567890abcdefghijklmn'") is not None
    )
    assert rule.pattern.search("STRIPE_KEY = 'sk_test_123'") is None
    assert rule.severity == "high"


def test_slack_webhook_rule():
    rule = next(r for r in SECRET_RULES if r.id == "slack-webhook")
    assert (
        rule.pattern.search(
            "URL: https://hooks.slack.com/"
            + "services/T00000000/"
            + "B00000000/"
            + "XXXXXXXXXXXXXXXXXXXXXXXX"
        )
        is not None
    )
    assert rule.pattern.search("https://hooks.slack.com/services/invalid") is None
    assert rule.severity == "high"


def test_python_eval_exec_rule():
    rule = next(r for r in SAST_RULES if r.id == "python-eval-exec")
    assert rule.pattern.search("eval(some_code)") is not None
    assert rule.pattern.search("exec (code)") is not None
    assert rule.pattern.search("pickle.loads(data)") is not None
    assert rule.pattern.search("evaluate()") is None
    assert rule.severity == "high"
