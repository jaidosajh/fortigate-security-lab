from contextlib import redirect_stdout, redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest
from tools.policy_audit import audit, parse_policies, main as audit_main
from tools.log_triage import triage, main as log_main

ROOT = Path(__file__).resolve().parents[1]
RISK = (ROOT / "samples/risky-policies.conf").read_text()
EVENT = 'type=traffic subtype=forward srcip=10.10.30.10 dstip=10.10.20.10 dstport=443 action=deny'


class PolicyTests(unittest.TestCase):
    def test_lab_configuration_passes(self):
        result = audit((ROOT / "configs/hq-policies.conf").read_text())
        self.assertEqual(result["policies_parsed"], 5)
        self.assertEqual(result["findings"], [])

    def test_risky_fixture_has_four_specific_findings(self):
        self.assertEqual({f["code"] for f in audit(RISK)["findings"]},
                         {"ANY_SERVICE", "ANY_ADDRESS", "ANY_INTERFACE", "LOGGING_INCOMPLETE"})

    def test_default_logging_flagged(self):
        self.assertIn("LOGGING_INCOMPLETE", {f["code"] for f in audit(RISK.replace('        set logtraffic disable\n', ''))["findings"]})

    def test_disabled_policy_skipped(self):
        self.assertEqual(audit(RISK.replace('set action accept', 'set status disable\n        set action accept'))["findings"], [])

    def test_wide_deny_is_valid_when_logged(self):
        self.assertEqual(audit(RISK.replace('set action accept', 'set action deny').replace('logtraffic disable', 'logtraffic all'))["findings"], [])

    def test_incomplete_and_unterminated_input(self):
        for bad in [RISK.replace('        set srcaddr "all"\n', ''), RISK.rsplit('end', 1)[0], '']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_policies(bad)

    def test_duplicate_policy_rejected(self):
        with self.assertRaises(ValueError):
            parse_policies(RISK + RISK)

    def test_vdom_and_nested_tables_rejected(self):
        for bad in ['config vdom\nedit root\n' + RISK + 'next\nend', RISK.replace('set action accept', 'config nested\nend\nset action accept')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_policies(bad)

    def test_mutation_commands_and_invalid_action_rejected(self):
        for bad in [RISK.replace('set action accept', 'unset action'), RISK.replace('set action accept', 'set action ipsec'), RISK.replace('set logtraffic disable', 'set logtraffic bogus')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_policies(bad)

    def test_policy_cli_exit_contract(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(audit_main([str(ROOT / 'configs/hq-policies.conf'), '--fail-on-findings']), 0)
            self.assertEqual(audit_main([str(ROOT / 'samples/risky-policies.conf'), '--fail-on-findings']), 1)
            self.assertEqual(audit_main([str(ROOT / 'does-not-exist')]), 2)


class LogTests(unittest.TestCase):
    def test_synthetic_result(self):
        result = triage((ROOT / 'samples/traffic.log').read_text(), 3)
        self.assertEqual(result['events_parsed'], 6)
        self.assertEqual(result['denied_events'], 4)
        self.assertEqual(result['sources'][0], {'srcip': '10.10.30.10', 'denied_events': 3,
                         'destination_ports': [22, 445, 3389], 'needs_review': True})
        self.assertFalse(result['sources'][1]['needs_review'])

    def test_quoted_message_and_ipv6(self):
        result = triage(EVENT.replace('10.10.30.10', '2001:db8::1') + ' msg="contains spaces and x=y"')
        self.assertEqual(result['sources'][0]['srcip'], '2001:db8::1')

    def test_non_forward_and_accept_not_denied(self):
        result = triage('type=event msg="admin log"\n' + EVENT.replace('action=deny', 'action=accept'))
        self.assertEqual(result['non_forward_events_ignored'], 1)
        self.assertEqual(result['denied_events'], 0)

    def test_threshold_boundary(self):
        self.assertTrue(triage(EVENT, 1)['sources'][0]['needs_review'])
        self.assertFalse(triage(EVENT, 2)['sources'][0]['needs_review'])
        with self.assertRaises(ValueError):
            triage(EVENT, 0)

    def test_bad_logs_rejected(self):
        for bad in ['', EVENT+' action=accept', EVENT.replace('10.10.30.10', '999.0.0.1'), EVENT.replace('443', '65536'), EVENT.replace('type=traffic ', ''), EVENT+' msg="unterminated', '<134> '+EVENT, EVENT.replace('srcip=10.10.30.10 ', '')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                triage(bad)

    def test_log_cli_exit_contract(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(log_main([str(ROOT / 'samples/traffic.log')]), 0)
            self.assertEqual(log_main([str(ROOT / 'samples/traffic.log'), '--threshold', '0']), 2)


if __name__ == '__main__':
    unittest.main()
