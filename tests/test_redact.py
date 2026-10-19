from secops_copilot.redact import redact


def test_each_pattern():
    text = "\n".join([
        "aws AKIAIOSFODNN7EXAMPLE used",
        "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 pushed",
        "slack xoxb-123456789012-abcdefghijkl posted",
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.c2lnbmF0dXJlc2lnbmF0dXJl here",  # gitleaks:allow (fake value for the redaction tests)
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "db postgres://app:S3cretPass@db.internal/app",
        'config password="hunter22" api_key=abcd1234efgh',  # gitleaks:allow (fake value for the redaction tests)
        "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
        "card 4111 1111 1111 1111 charged",
    ])
    out, counts = redact(text)
    assert counts == {"aws_access_key": 1, "github_token": 1, "slack_token": 1, "jwt": 1, "bearer_token": 1,
                      "url_password": 1, "secret_assignment": 2, "private_key": 1, "card_number": 1}
    for secret in ("AKIAIOSFODNN7EXAMPLE", "ghp_abcdef", "xoxb-", "eyJhbGci", "abcdefghijklmnopqrstuvwxyz",
                   "S3cretPass", "hunter22", "abcd1234efgh", "MIIB", "4111 1111"):
        assert secret not in out
    assert "postgres://app:[REDACTED:url_password]@db.internal/app" in out
    assert 'password="[REDACTED:secret]"' in out and "Bearer [REDACTED:bearer_token]" in out


def test_log_lines_are_left_alone():
    lines = ["Oct 17 02:11:04 bastion-01 sshd[2217]: Failed password for dave from 203.0.113.9 port 51022 ssh2",
             "sudo:     dave : TTY=pts/2 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/export.tgz /home",
             "order 1234567890123 shipped",  # fails Luhn: not a card
             "useradd[2290]: new user: name=support2, UID=1010"]
    for ln in lines:
        out, counts = redact(ln)
        assert out == ln and counts == {}, ln
