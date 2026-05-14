import unittest

from core.graph import AgentGraph


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.graph = AgentGraph()

    def test_benign_management_event_short_circuits(self):
        event = {
            "_id": "evt-benign",
            "timestamp": "2026-04-14T12:00:00Z",
            "event_type": "fileinfo",
            "app_proto": "http",
            "src_ip": "192.168.56.1",
            "src_port": 52902,
            "dest_ip": "192.168.56.10",
            "dest_port": 9000,
            "http_url": "/api/cluster/metrics/multiple",
            "http_status": 200,
            "fileinfo_filename": "/api/cluster/metrics/multiple",
        }

        trace = self.graph.process_event(event)

        self.assertIn(trace["planner_result"]["route"], {"skip", "fast_detect"})
        self.assertEqual(trace["detection_result"]["verdict"], "benign")

    def test_high_risk_signature_triggers_response_plan(self):
        event = {
            "_id": "evt-mal",
            "timestamp": "2026-04-14T12:02:00Z",
            "event_type": "alert",
            "app_proto": "http",
            "src_ip": "203.0.113.99",
            "src_port": 45444,
            "dest_ip": "192.168.56.1",
            "dest_port": 443,
            "alert_severity": 1,
            "alert_signature": "SQL injection exploit attempt",
            "alert_category": "Web Application Attack",
            "http_url": "/admin/login",
            "flow_pkts_toserver": 180,
            "flow_pkts_toclient": 120,
            "flow_bytes_toserver": 480000,
            "flow_bytes_toclient": 220000,
        }

        trace = self.graph.process_event(event)

        self.assertEqual(trace["detection_result"]["verdict"], "malicious")
        self.assertEqual(trace["response_result"]["action"], "block_source_ip_on_firewall")
        self.assertIn(trace["response_result"]["status"], {"dry_run", "completed", "pending_remote_execution"})

    def test_trace_contract_contains_required_sections(self):
        event = {
            "_id": "evt-contract",
            "timestamp": "2026-04-14T12:03:00Z",
            "event_type": "alert",
            "src_ip": "198.51.100.10",
            "dest_ip": "192.168.56.10",
            "alert_signature": "SURICATA SSH invalid banner",
            "alert_severity": 3,
        }

        trace = self.graph.process_event(event)
        for key in (
            "event_id",
            "timestamp",
            "raw_event",
            "normalized_features",
            "planner_result",
            "detection_result",
            "response_result",
            "asset_context",
            "trace_metadata",
        ):
            self.assertIn(key, trace)


if __name__ == "__main__":
    unittest.main()
