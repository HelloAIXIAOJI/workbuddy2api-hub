"""Pin the account-level failure governance: soft backoff, breaker, degrade.

Repeated soft limits used to get the same short cooldown every time, so an
account that was clearly being throttled kept getting handed out; hard and
unknown failures had no accumulated penalty at all. The panel project's pool
cools a soft-limited credential exponentially (10m, 20m, ... capped at 2h),
trips a breaker after 3 consecutive hard failures (30m doubling to 6h) and
degrades after 5 unknown ones (10m doubling to 2h). A served request clears
everything.

No network: accounts are built from dicts and written to a temp directory.
"""
import base64
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMP = tempfile.mkdtemp(prefix="wb-pool-backoff-")
os.environ["ACCOUNTS_DIR"] = os.path.join(_TMP, "accounts")
os.makedirs(os.environ["ACCOUNTS_DIR"], exist_ok=True)
# 6004 的请求路径会写 limit-events.jsonl。指到临时目录，否则这些用例会把
# 事件写进真实用量目录；此前的用例都不触发它，所以没有设过。
os.environ["WB_PROXY_USAGE_DIR"] = os.path.join(_TMP, "usage")
os.makedirs(os.environ["WB_PROXY_USAGE_DIR"], exist_ok=True)

import wb_accounts as A
import wb_proxy
import wb_settings


INTL_ISS = "https://www.workbuddy.ai/auth/realms/copilot"

# The real 429 shapes from the incident environment (issue #70, sanitized:
# requestId removed, UIDs/hosts never present). S1 is 229 of the 263 recorded
# 429s; S2 is the one provably intl body with no reset field; S3/S4 name a reset
# clock and are the controls.
S1_BARE = "usage exceeds frequency limit"
# The log keeps str(message)[:200], so S2 survives only as this truncated
# prefix; S2_INTL_JSON is the same body closed into valid JSON, which is the
# form that exercises the code-number path.
S2_INTL_RECORDED = ('{"code":14003,"msg":"too many requests",'
                    '"retry_policy":{"retry":true},'
                    '"displayMsg":{"en":"Too many requests. Please retry later.",'
                    '"zh":"请求过于频繁，请稍后重试。","z')
S2_INTL_JSON = ('{"code":14003,"msg":"too many requests",'
                '"retry_policy":{"retry":true},'
                '"displayMsg":{"en":"Too many requests. Please retry later.",'
                '"zh":"请求过于频繁，请稍后重试。"}}')
# The gateway reads up to 600 characters while the usage log kept only 200, so
# the real body carries more than the recorded prefix. The tail below is the
# shape that tail can have; `accountId` / `credentialId` are field names.
S2_INTL_FULL = ('{"code":14003,"msg":"too many requests",'
                '"accountId":"<redacted>","credentialId":"<redacted>",'
                '"requestId":"<redacted>","retry_policy":{"retry":true},'
                '"displayMsg":{"en":"Too many requests. Please retry later.",'
                '"zh":"请求过于频繁，请稍后重试。"},"ts":1790500000}')
S3_INTL_6004 = ('{"code":6004,"msg":"usage exceeds frequency limit, but don\'t '
                'worry, your usage will reset at 2026-10-06 21:00:09 UTC+8, '
                'alternatively, you can switch to the other models to continue '
                'using it."}')
S4_CN_6004 = ('{"code":6004,"msg":"您的使用量已超出频率限制，'
              '将在 2026-10-06 14:45:04 UTC+8 重置，'
              '您也可以切换其他模型继续使用。"}')


def jwt(iss=INTL_ISS, sub="u-1"):
    def part(obj):
        raw = base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
        return raw.rstrip("=")
    return "%s.%s.sig" % (part({"alg": "RS256", "typ": "JWT"}),
                          part({"iss": iss, "sub": sub, "exp": 4102444800}))


def load_account(uid="u-backoff-1"):
    directory = os.path.join(_TMP, uid)
    os.makedirs(directory, exist_ok=True)
    data = {"uid": uid, "domain": "www.workbuddy.ai", "realm": "intl",
            "accessToken": jwt()}
    with open(os.path.join(directory, uid + ".json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    accounts = A.AccountPool(directory).load()
    assert len(accounts) == 1
    return accounts[0]


class BackoffMathTests(unittest.TestCase):
    def test_soft_backoff_doubles_and_caps(self):
        self.assertEqual(A.soft_backoff(1), A.SOFT_RATE_BASE)
        self.assertEqual(A.soft_backoff(2), A.SOFT_RATE_BASE * 2)
        self.assertEqual(A.soft_backoff(4), A.SOFT_RATE_BASE * 8)
        self.assertEqual(A.soft_backoff(50), A.SOFT_RATE_MAX)

    def test_breaker_starts_at_the_threshold_and_caps(self):
        self.assertEqual(A.breaker_backoff(A.BREAKER_THRESHOLD), A.BREAKER_COOLDOWN)
        self.assertEqual(A.breaker_backoff(A.BREAKER_THRESHOLD + 1),
                         A.BREAKER_COOLDOWN * 2)
        self.assertEqual(A.breaker_backoff(99), A.BREAKER_COOLDOWN_MAX)

    def test_degrade_starts_at_the_threshold_and_caps(self):
        self.assertEqual(A.degrade_backoff(A.DEGRADE_THRESHOLD), A.DEGRADE_COOLDOWN)
        self.assertEqual(A.degrade_backoff(A.DEGRADE_THRESHOLD + 2),
                         A.DEGRADE_COOLDOWN * 4)
        self.assertEqual(A.degrade_backoff(99), A.DEGRADE_COOLDOWN_MAX)

    def test_the_real_unscoped_shapes_are_recognised(self):
        """S1 (87% of the recorded 429s) and the intl 14003 body."""
        self.assertTrue(wb_proxy.rate_limit_is_soft_shape(S1_BARE))
        self.assertTrue(wb_proxy.rate_limit_is_soft_shape(S2_INTL_JSON))
        # The recorded form is truncated mid-JSON and still matches on the text.
        self.assertTrue(wb_proxy.rate_limit_is_soft_shape(S2_INTL_RECORDED))
        self.assertEqual(wb_proxy.rate_limit_code(S2_INTL_JSON), 14003)
        self.assertIsNone(wb_proxy.rate_limit_code(S1_BARE), "S1 is not JSON")
        # An unrelated 429 body must not be claimed as a rate-limit shape.
        self.assertFalse(wb_proxy.rate_limit_is_soft_shape("<html>bad gateway</html>"))
        self.assertFalse(wb_proxy.rate_limit_is_soft_shape(""))

    def test_none_of_the_real_shapes_is_account_level_without_evidence(self):
        """S1/S2 carry no timestamp; S3/S4 are the parsed controls.

        This used to be `rate_limit_is_account_level(d, None) == True`, which
        made "no parsable timestamp" itself the account-level evidence: S1 and
        S2 each bought the credential 600s doubling to 7200s, so a handful of
        them left a whole realm cooling while the panel test still reported the
        credential healthy.
        """
        for detail in (S1_BARE, S2_INTL_JSON, S2_INTL_RECORDED):
            self.assertIsNone(wb_proxy.parse_rate_limit_reset(detail), detail)
            self.assertFalse(wb_proxy.rate_limit_is_account_level(detail, None), detail)
        # S3/S4 parse to exactly the instant their text names (H's table).
        self.assertEqual(wb_proxy.parse_rate_limit_reset(S3_INTL_6004), 1791291609)
        self.assertEqual(wb_proxy.parse_rate_limit_reset(S4_CN_6004), 1791269104)
        for detail in (S3_INTL_6004, S4_CN_6004):
            reset_at = wb_proxy.parse_rate_limit_reset(detail)
            self.assertFalse(wb_proxy.rate_limit_is_account_level(detail, reset_at), detail)
        # Nor is a body we cannot read at all.
        self.assertFalse(wb_proxy.rate_limit_is_account_level("", None))

    def test_metadata_field_names_are_not_scope_evidence(self):
        """`accountId` is a field name, not "the account is rate limited".

        The gateway reads up to 600 characters of the 429 body; a substring test
        read that metadata tail as credential evidence and put the 600s -> 7200s
        ladder back in play for the most common intl shape.
        """
        self.assertTrue(wb_proxy.rate_limit_is_soft_shape(S2_INTL_FULL))
        self.assertIsNone(wb_proxy.parse_rate_limit_reset(S2_INTL_FULL))
        self.assertIsNone(wb_proxy.credential_scope_phrase(S2_INTL_FULL))
        self.assertFalse(wb_proxy.rate_limit_is_account_level(S2_INTL_FULL, None))
        for metadata in ('{"accountId":"x"}', '{"account_id":"x"}',
                         '{"accountName":"x"}', '{"credentialId":"x"}',
                         '{"subaccount":"x"}', '{"accountIds":["x"]}'):
            self.assertFalse(wb_proxy.rate_limit_is_account_level(metadata, None),
                             metadata)
        # Scope has to be said, not implied by a field name.
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"msg":"account-level rate limit reached"}', None))
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"msg":"too many requests for this account"}', None))
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"msg":"该账号请求过于频繁"}', None))
        self.assertEqual(wb_proxy.credential_scope_phrase(
            '{"msg":"This Account is rate limited"}'), "this account")
        self.assertIsNone(wb_proxy.credential_scope_phrase(S1_BARE))

    def test_the_two_ladders_do_not_feed_each_other(self):
        """One shared counter pushed either ladder to the other's ceiling.

        Four unscoped 429s left soft_streak at 4, so the first genuinely
        credential-scoped 429 started at 600 * 2**4 and reached the 7200s cap
        instead of starting at 600s; the reverse direction lifted the unscoped
        ladder the same way.
        """
        account = load_account("u-domains")
        for _ in range(4):
            account.note_unscoped_rate("glm-5.3")
        self.assertEqual(account.unscoped_streak, 4)
        self.assertEqual(account.soft_streak, 0)
        self.assertEqual(account.note_soft_rate("HTTP 429 (account soft rate)"),
                         A.SOFT_RATE_BASE,
                         "the credential ladder starts at its own base")

        other = load_account("u-domains-reverse")
        other.note_soft_rate("HTTP 429 (account soft rate)")
        other.note_soft_rate("HTTP 429 (account soft rate)")
        self.assertEqual(other.soft_streak, 2)
        self.assertEqual(other.unscoped_streak, 0)
        self.assertEqual(other.note_unscoped_rate("glm-5.3"),
                         A.SOFT_RATE_UNVERIFIED_BASE,
                         "the unscoped ladder starts at its own base")

    def test_a_served_request_clears_both_streaks(self):
        account = load_account("u-both-streaks")
        account.note_soft_rate("HTTP 429 (account soft rate)")
        account.note_unscoped_rate("glm-5.3")
        self.assertEqual((account.soft_streak, account.unscoped_streak), (1, 1))
        account.note_success(model="glm-5.3")
        self.assertEqual(account.soft_streak, 0)
        self.assertEqual(account.unscoped_streak, 0)
        self.assertEqual(account.public()["unscopedStreak"], 0)

    def test_the_unscoped_ladder_starts_short_and_caps_at_one_credential_tier(self):
        """S1 is the most common shape, so its ceiling cannot be the 2h one."""
        self.assertEqual(A.unverified_soft_backoff(1), 60.0)
        self.assertEqual(A.unverified_soft_backoff(2), 120.0)
        self.assertEqual(A.unverified_soft_backoff(4), 480.0)
        self.assertEqual(A.unverified_soft_backoff(5), 600.0)
        self.assertEqual(A.unverified_soft_backoff(50), A.SOFT_RATE_UNVERIFIED_MAX)
        self.assertEqual(A.SOFT_RATE_UNVERIFIED_MAX, A.SOFT_RATE_BASE)
        self.assertLess(A.SOFT_RATE_UNVERIFIED_MAX, A.SOFT_RATE_MAX)

    def test_an_unscoped_429_parks_the_model_not_the_credential(self):
        account = load_account("u-unscoped")
        first = account.note_unscoped_rate("glm-5.3")
        self.assertEqual(first, 60.0)
        account.note_error("HTTP 429 (model throttled)", model="glm-5.3",
                           cooldown=first)
        second = account.note_unscoped_rate("glm-5.3")
        self.assertEqual(second, 120.0)
        account.note_error("HTTP 429 (model throttled)", model="glm-5.3",
                           cooldown=second)
        self.assertEqual(account.unscoped_streak, 2)
        self.assertEqual(account.soft_streak, 0, "the credential counter is untouched")
        # The credential is never parked, and a sibling model stays usable -
        # that is the difference from note_soft_rate().
        self.assertEqual(account.cooldown_until, 0.0)
        self.assertEqual(account.throttle_wait(), 0)
        self.assertTrue(account.ready(model="another-model"))
        self.assertFalse(account.ready(model="glm-5.3"))

    def test_only_credential_wording_is_account_level(self):
        """Positive evidence keeps the 10m -> 2h ladder reachable.

        Provisional by design: the phrase list is short because no captured body
        has shown yet what a genuine account-level 429 says.
        """
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"message":"too many requests for this account"}', None))
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"msg":"该账号请求过于频繁"}', None))
        # A reset clock still wins - that is the model-scoped form.
        self.assertFalse(wb_proxy.rate_limit_is_account_level(
            '{"message":"account rate limit, reset at 2026-10-09 12:00:00 UTC"}',
            time.time() + 60))

    def test_a_genuine_account_level_429_still_backs_off(self):
        account = load_account("u-account-level")
        self.assertTrue(wb_proxy.rate_limit_is_account_level(
            '{"message":"too many requests for this account"}', None))
        self.assertEqual(account.note_soft_rate("HTTP 429 (account soft rate)"),
                         A.SOFT_RATE_BASE)
        self.assertEqual(account.note_soft_rate("HTTP 429 (account soft rate)"),
                         A.SOFT_RATE_BASE * 2)
        self.assertEqual(account.soft_streak, 2)

    def test_reset_clock_is_parsed_for_both_realm_wordings(self):
        cn = ('{"code":6004,"msg":"您的使用量已超出频率限制，'
              '将在 2026-10-09 14:44:59 UTC+8 重置。"}')
        intl = ('{"code":6004,"message":"your usage will reset at '
                '2026-10-09 14:44:59 UTC+8"}')
        cn_reset = wb_proxy.parse_rate_limit_reset(cn)
        self.assertEqual(cn_reset, wb_proxy.parse_rate_limit_reset(intl))
        self.assertIsNotNone(cn_reset)
        # 14:44:59 UTC+8 is the same wall clock as 06:44:59 UTC.
        self.assertEqual(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cn_reset)),
                         "2026-10-09 06:44:59")
        self.assertIsNone(wb_proxy.parse_rate_limit_reset('{"code":429}'))


class AccountGovernanceTests(unittest.TestCase):
    def test_soft_rate_backs_off_and_counts_the_streak(self):
        account = load_account("u-soft")
        first = account.note_soft_rate("HTTP 429 (account soft rate)")
        second = account.note_soft_rate("HTTP 429 (account soft rate)")
        self.assertEqual(account.soft_streak, 2)
        self.assertEqual(first, A.SOFT_RATE_BASE)
        self.assertEqual(second, A.SOFT_RATE_BASE * 2)
        self.assertGreater(account.throttle_wait(), 0)
        view = account.public()
        self.assertEqual(view["softStreak"], 2)
        self.assertTrue(view["inCooldown"])

    def test_breaker_needs_three_hard_failures(self):
        account = load_account("u-breaker")
        account.note_failure("HTTP 502")
        account.note_failure("HTTP 502")
        self.assertEqual(account.throttle_wait(), 0)
        account.note_failure("HTTP 503")
        self.assertGreater(account.breaker_until, 0)
        self.assertGreater(account.throttle_wait(), 0)
        self.assertTrue(account.public()["breakerFor"])

    def test_unknown_failures_degrade_after_the_threshold(self):
        account = load_account("u-degrade")
        account.note_unknown_failure("connection: TimeoutError")
        account.note_unknown_failure("connection: TimeoutError")
        self.assertEqual(account.throttle_wait(), 0)
        # Unknown failures also feed the shared breaker counter, so the wrap
        # is asserted past both thresholds; the degrade window itself starts
        # at DEGRADE_THRESHOLD.
        for _ in range(A.DEGRADE_THRESHOLD - 2):
            account.note_unknown_failure("connection: TimeoutError")
        self.assertEqual(account.degrade_count, A.DEGRADE_THRESHOLD)
        self.assertGreater(account.degrade_until, 0)
        self.assertGreater(account.throttle_wait(), 0)
        self.assertTrue(account.public()["degradeFor"])

    def test_success_clears_every_penalty(self):
        account = load_account("u-success")
        account.note_soft_rate("HTTP 429 (account soft rate)")
        for _ in range(A.BREAKER_THRESHOLD):
            account.note_failure("HTTP 502")
        account.note_unknown_failure("connection: TimeoutError")
        account.note_success(model="deepseek-v4.1-flash")
        self.assertEqual(account.throttle_wait(), 0)
        self.assertEqual(account.soft_streak, 0)
        self.assertEqual(account.fails, 0)
        self.assertEqual(account.degrade_count, 0)
        self.assertEqual(account.breaker_until, 0.0)
        self.assertEqual(account.degrade_until, 0.0)
        self.assertEqual(account.public()["lastError"], "")


class PanelTestSuccessTests(unittest.TestCase):
    """A green panel test is a served request, so it must clear the streak.

    /accounts/test calls clear_error() on success, which clears the visible
    cooldown fields but never touched soft_streak - the counter note_success()
    resets. The panel could therefore show an account as usable while the next
    account-level 429 resumed the backoff ladder from the stale streak.
    """

    class _Route(object):
        """Just enough handler for the real _route_accounts_test()."""

        def _json(self, code, obj):
            self.code, self.body = code, obj
            return code, obj

    class _Response(object):
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    def _drive_panel_test(self, account):
        """Run the real route with a stubbed upstream answer."""
        class Pool(object):
            def get(self, uid):
                return account if uid == account.uid else None

        route = self._Route()
        old = (wb_proxy.POOL, A.urlopen, wb_proxy.aggregate_stream)
        wb_proxy.POOL = Pool()
        A.urlopen = lambda *args, **kwargs: self._Response()
        wb_proxy.aggregate_stream = lambda resp, model, key: {
            "choices": [{"message": {"content": "OK"}}]}
        try:
            return wb_proxy.Handler._route_accounts_test(route, {"uid": account.uid})
        finally:
            wb_proxy.POOL, A.urlopen, wb_proxy.aggregate_stream = old

    def test_a_successful_panel_test_clears_the_streak(self):
        account = load_account("u-panel-test")
        account.note_soft_rate("HTTP 429 (account soft rate)")
        account.note_soft_rate("HTTP 429 (account soft rate)")
        self.assertEqual(account.soft_streak, 2)

        code, body = self._drive_panel_test(account)

        self.assertEqual(code, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(account.soft_streak, 0)
        self.assertEqual(account.throttle_wait(), 0)
        self.assertEqual(account.public()["softStreak"], 0)

    def test_a_stale_streak_does_not_resume_on_the_next_event(self):
        account = load_account("u-panel-test-stale")
        for _ in range(3):
            account.note_soft_rate("HTTP 429 (account soft rate)")
        self.assertEqual(account.soft_streak, 3)

        self._drive_panel_test(account)

        # The next account-level 429 starts the ladder over rather than
        # continuing from the streak the panel test should have cleared.
        wait = account.note_soft_rate("HTTP 429 (account soft rate)")
        self.assertEqual(account.soft_streak, 1)
        self.assertEqual(wait, A.SOFT_RATE_BASE)

    def test_a_panel_test_keeps_other_models_throttled(self):
        """The narrow success path must not lift sibling model cooldowns."""
        account = load_account("u-panel-test-siblings")
        account.note_error("HTTP 429 (model throttled)", model="glm-5.3",
                           cooldown=600)

        self._drive_panel_test(account)

        self.assertFalse(account.ready(model="glm-5.3"))
        self.assertIn("glm-5.3", [item["model"]
                                  for item in account.public()["modelCooldowns"]])


class RetryRoundChargeTests(unittest.TestCase):
    """One client request must not charge the same account twice (issue #271).

    After a transient the retry loop clears `tried` so the whole pool is
    re-scanned. With a single usable account that hands the same account back,
    and before this guard it was charged again: two fails out of one request,
    so two blips could trip the 3-failure breaker instead of three. The pool
    being nearly empty is exactly when this bites, which is the incident
    environment.
    """

    def _drive(self, account, urlopen):
        class Pool(object):
            accounts = [account]
            affinity = type("Affinity", (), {
                "unbind": lambda self, key: None,
                "demote": lambda self, key, uid=None: None})()

            def count_ready(self, realm, model=None):
                return 1

            def pick_for_session(self, realm, session_key=None, exclude=(),
                                 model=None, page=None):
                return None if account.uid in exclude else account

            def list_public(self):
                return []

            def apply_daily_token_limit(self, *a, **k):
                return 0

            def apply_daily_credit_limit(self, *a, **k):
                return 0

            def apply_model_daily_token_limit(self, *a, **k):
                return 0

            def apply_remaining_weights(self, weights=None):
                return weights or {}

        old_pool, old_urlopen = wb_proxy.POOL, A.urlopen
        wb_proxy.POOL = Pool()
        A.urlopen = urlopen
        try:
            with mock.patch.object(wb_proxy, "ACCOUNTS_DIR",
                                   os.path.join(_TMP, account.uid)):
                try:
                    wb_proxy.open_upstream(
                        {"model": "deepseek-v4.1-flash",
                         "messages": [{"role": "user", "content": "hi"}]},
                        target_realm="intl")
                except Exception:
                    pass
        finally:
            wb_proxy.POOL, A.urlopen = old_pool, old_urlopen

    def test_a_transport_blip_charges_the_account_once(self):
        account = load_account("u-charge-transient")

        def urlopen(req, timeout=30, proxy=""):
            raise urllib.error.URLError("The handshake operation timed out")

        with mock.patch.object(time, "sleep"):
            self._drive(account, urlopen)
        # The retry round re-picked the account; it must still be one charge.
        self.assertEqual(account.fails, 1)
        self.assertEqual(account.degrade_count, 1)

    def test_a_gateway_5xx_charges_the_account_once(self):
        account = load_account("u-charge-5xx")

        def urlopen(req, timeout=30, proxy=""):
            raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, None)

        with mock.patch.object(time, "sleep"):
            self._drive(account, urlopen)
        self.assertEqual(account.fails, 1)

    def test_the_guard_is_per_request_not_per_process(self):
        # A second request is a second chance to be charged: the guard must not
        # leak across requests (it would hide a genuinely failing account).
        account = load_account("u-charge-two-requests")

        def urlopen(req, timeout=30, proxy=""):
            raise urllib.error.URLError("connection reset by peer")

        with mock.patch.object(time, "sleep"):
            self._drive(account, urlopen)
            self._drive(account, urlopen)
        self.assertEqual(account.fails, 2)


class Throttle429ModeTests(unittest.TestCase):
    """The panel's 429 handling switch: park the model, or relay and move on.

    cooldown (the default) is the behaviour that predates the switch and must
    stay exactly what it was. passthrough is the workbuddy2api behaviour: the
    429 reaches the client and the account stays in rotation, so the next
    request - an agent's next tool call, seconds later - goes upstream again
    instead of being answered from a local cooldown the upstream never asked
    for.
    """

    #: The intl frequency-limit body (code 14003) from the incident
    #: environment: no reset clock, so nothing scopes it to the credential and
    #: it becomes a window on one model.
    SOFT_429 = ('{"code":14003,"msg":"too many requests",'
                '"displayMsg":{"en":"Too many requests. Please retry later."}}')
    #: A genuine quota cap (code 6004), the one 429 shape that carries a reset
    #: clock and is therefore a statement about the model window budget.
    CAP_429 = ('{"code":6004,"msg":"usage exceeds frequency limit, '
               'your usage will reset at 2030-01-01 00:00:00 UTC+8."}')
    #: An intl free cap model (see FREE_CAP_MODELS): the only scope the
    #: persistent-disable path covers.
    CAP_MODEL = "hy3"

    def _settings_dir(self, mode):
        directory = tempfile.mkdtemp(prefix="throttle-429-")
        if mode is not None:
            wb_settings.set_throttle_429(directory, mode)
        return directory

    def _drive(self, account, model, body, mode):
        """Run the real open_upstream() into a stubbed 429; return the failure."""
        error = urllib.error.HTTPError(
            "https://upstream.invalid", 429, "rate limit", {},
            io.BytesIO(body.encode("utf-8")))

        class Pool(object):
            accounts = [account]
            affinity = type("Affinity", (), {
                "unbind": lambda self, key: None,
                "demote": lambda self, key, uid=None: None})()

            def count_ready(self, realm, model=None):
                return 1

            def pick_for_session(self, realm, session_key=None, exclude=(),
                                 model=None, page=None):
                return None if account.uid in exclude else account

            def list_public(self):
                return []

            def apply_remaining_weights(self, weights=None):
                return weights or {}

            def apply_daily_token_limit(self, *a, **k):
                return 0

            def apply_daily_credit_limit(self, *a, **k):
                return 0

            def apply_model_daily_token_limit(self, *a, **k):
                return 0

        old_pool, old_urlopen = wb_proxy.POOL, A.urlopen
        wb_proxy.POOL = Pool()
        A.urlopen = lambda *args, **kwargs: (_ for _ in ()).throw(error)
        try:
            with mock.patch.object(wb_proxy, "ACCOUNTS_DIR",
                                   self._settings_dir(mode)):
                with self.assertRaises(wb_proxy.RateLimited) as caught:
                    wb_proxy.open_upstream(
                        {"model": model,
                         "messages": [{"role": "user", "content": "hi"}]},
                        target_realm="intl")
        finally:
            wb_proxy.POOL, A.urlopen = old_pool, old_urlopen
        return caught.exception

    def test_the_switch_defaults_to_the_historical_cooldown(self):
        """An install that never touched the setting keeps the old behaviour."""
        directory = tempfile.mkdtemp(prefix="throttle-429-default-")
        self.assertEqual(wb_settings.throttle_429(directory), "cooldown")
        self.assertEqual(wb_settings.set_throttle_429(directory, "passthrough"),
                         "passthrough")
        self.assertEqual(wb_settings.throttle_429(directory), "passthrough")
        self.assertEqual(wb_settings.set_throttle_429(directory, "cooldown"),
                         "cooldown")
        # A hand-edited value must never silently disable throttling.
        with open(wb_settings.settings_path(directory), "w",
                  encoding="utf-8") as fh:
            json.dump({"throttle_429": "off"}, fh)
        self.assertEqual(wb_settings.throttle_429(directory), "cooldown")

    def test_cooldown_mode_parks_the_model(self):
        account = load_account("u-throttle-cooldown")
        self._drive(account, "glm-5.3", self.SOFT_429, "cooldown")
        self.assertEqual(account.unscoped_streak, 1)
        self.assertFalse(account.ready(model="glm-5.3"))
        self.assertTrue(account.public()["modelCooldowns"])

    def test_passthrough_mode_keeps_the_model_in_rotation(self):
        """The 2api behaviour: relay the 429, park nobody."""
        account = load_account("u-throttle-passthrough")
        self._drive(account, "glm-5.3", self.SOFT_429, "passthrough")
        self.assertEqual(account.unscoped_streak, 0,
                         "the unscoped model ladder must not advance")
        self.assertEqual(account.soft_streak, 0,
                         "the credential ladder must not advance")
        self.assertEqual(account.throttle_wait(model="glm-5.3"), 0)
        self.assertTrue(account.ready(model="glm-5.3"))
        self.assertEqual(account.public()["modelCooldowns"], [])
        # The observation stays visible on the account row; nothing that
        # ready()/throttle_wait() reads is touched by it.
        self.assertIn("429", account.public()["lastError"])

    def test_passthrough_still_honours_a_genuine_quota_cap(self):
        """6004 is quota exhaustion, not a frequency limit.

        The switch governs the frequency windows. A model whose upstream quota
        window is spent stays parked until the reset instant the upstream
        named, in both modes - otherwise the gateway would hammer a window that
        cannot serve anything until then.
        """
        account = load_account("u-throttle-cap")
        self._drive(account, self.CAP_MODEL, self.CAP_429, "passthrough")
        self.assertGreater(account.cap_until(self.CAP_MODEL), time.time())
        self.assertFalse(account.ready(model=self.CAP_MODEL))

    def test_passthrough_does_not_fabricate_a_sixty_second_retry(self):
        """Nothing is parked, so a 60s Retry-After would be invented here.

        retry_after_seconds() answers 60 when no account is cooling - correct in
        cooldown mode, but in passthrough it would hand the client a window the
        gateway itself decided not to impose.
        """
        account = load_account("u-throttle-retry-after")
        exc = self._drive(account, "glm-5.3", self.SOFT_429, "passthrough")
        self.assertLessEqual(exc.wait, wb_proxy.PASSTHROUGH_RETRY_AFTER)

    def test_passthrough_relays_the_upstream_retry_hint(self):
        account = load_account("u-throttle-retry-hint")
        body = '{"code":14003,"msg":"too many requests; retry in 51s"}'
        exc = self._drive(account, "glm-5.3", body, "passthrough")
        self.assertEqual(exc.wait, 51)

    def test_cooldown_mode_still_reports_the_cooldown(self):
        account = load_account("u-throttle-retry-cooldown")
        exc = self._drive(account, "glm-5.3", self.SOFT_429, "cooldown")
        # The reported wait is the cooldown itself (int()-truncated from the
        # remaining time), not the passthrough floor.
        self.assertGreater(exc.wait, wb_proxy.PASSTHROUGH_RETRY_AFTER)
        self.assertAlmostEqual(exc.wait, 60, delta=2)

    def test_passthrough_does_not_advance_the_credential_ladder(self):
        """A credential-scoped 429 must not buy the 600s -> 7200s ladder."""
        account = load_account("u-throttle-account-level")
        body = '{"message":"too many requests for this account"}'
        self._drive(account, "glm-5.3", body, "passthrough")
        self.assertEqual(account.soft_streak, 0)
        self.assertEqual(account.throttle_wait(), 0)
        self.assertTrue(account.ready(model="glm-5.3"))


class Throttle429SettingsRouteTests(unittest.TestCase):
    """The panel route must reject anything but the two documented modes.

    Coercing an unknown value instead would let a typo or a wrong-typed field
    silently change how every 429 is handled.
    """

    class _Route(object):
        def __init__(self, payload):
            self.payload = payload
            self.code = None
            self.body = None

        def _payload_or_error(self):
            return self.payload

        def _error(self, code, message, err_type=None):
            self.code, self.body = code, message
            return code, message

        def _json(self, code, obj):
            self.code, self.body = code, obj
            return code, obj

    def _save(self, payload, directory):
        route = self._Route(payload)
        with mock.patch.object(wb_proxy, "ACCOUNTS_DIR", directory):
            wb_proxy.Handler._handle_settings_save(route)
        return route

    def test_a_valid_mode_is_persisted_and_echoed(self):
        directory = tempfile.mkdtemp(prefix="throttle-route-")
        route = self._save({"throttle_429": "passthrough"}, directory)
        self.assertEqual(route.code, 200)
        self.assertEqual(route.body["throttle_429"], "passthrough")
        self.assertEqual(wb_settings.throttle_429(directory), "passthrough")

    def test_an_unknown_mode_is_rejected_without_writing(self):
        directory = tempfile.mkdtemp(prefix="throttle-route-bad-")
        for bad in ("off", "", None, True, 1, ["passthrough"], {"mode": "x"}):
            route = self._save({"throttle_429": bad}, directory)
            self.assertEqual(route.code, 400, repr(bad))
        self.assertEqual(wb_settings.throttle_429(directory), "cooldown",
                         "a rejected payload must not persist anything")


if __name__ == "__main__":
    unittest.main(verbosity=2)
