from __future__ import annotations

import pathlib
import re
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
GATEWAY = PROJECT / "gateway"
SERVICES = (
    "gateway", "controlplane", "agentproxy", "firmwareorigin",
    "generationcoordinator", "accountauthorization", "factorytimeauthority",
)


class ContentFreeTelemetryPolicyTests(unittest.TestCase):
    def read(self, path: str) -> str:
        return (PROJECT / path).read_text()

    def test_exact_seven_commands_load_and_wrap_product_runtime(self) -> None:
        for service in SERVICES:
            source = self.read(f"gateway/cmd/{service}/main.go")
            self.assertIn("internal/telemetry", source)
            self.assertRegex(
                source, re.compile(rf'telemetry\.LoadSettings\(\s*"{service}"')
            )
            self.assertIn("telemetry.New(context.Background(), traceSettings)", source)
            self.assertIn("traceRuntime.WrapHandler(", source)
            self.assertIn("traceRuntime.Shutdown(", source)
        commands = {
            path.parent.name
            for path in (GATEWAY / "cmd").glob("*/main.go")
            if "telemetry.LoadSettings(" in path.read_text()
        }
        self.assertEqual(commands, set(SERVICES))

    def test_span_attributes_and_operations_are_closed_and_content_free(self) -> None:
        source = self.read("gateway/internal/telemetry/http.go")
        for allowed in (
            'attribute.String("xiaozhi.operation"',
            'attribute.String("http.request.method"',
            'attribute.Int("http.response.status_code"',
            'attribute.String("xiaozhi.result_class"',
        ):
            self.assertIn(allowed, source)
        for forbidden in (
            'attribute.String("http.url"', 'attribute.String("url.',
            'attribute.String("http.request.header',
            'attribute.String("http.response.header',
            'attribute.String("exception.', 'RecordError(',
            'request.URL.String()', 'request.Host', 'request.Body',
            'response.Body"', 'request.Header.Get("Authorization")',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('clone.Header.Del("baggage")', source)
        self.assertIn('clone.Header.Del("tracestate")', source)
        self.assertIn('clone.Header.Del("traceparent")', source)

    def test_context_crosses_only_product_owned_internal_boundaries(self) -> None:
        source = self.read("gateway/internal/telemetry/http.go")
        for service in ("accountauthorization", "generationcoordinator"):
            self.assertRegex(source, re.compile(rf'"{service}":\s+true'))
        for operation in ("agent.provider", "push.apns", "push.fcm", "push.oauth"):
            self.assertIn(f'"{operation}":', source)
            line = next(value for value in source.splitlines() if f'"{operation}":' in value)
            self.assertIn("false", line)

    def test_runtime_rejects_standard_otel_surface_and_uses_mtls_exporter(self) -> None:
        settings = self.read("gateway/internal/telemetry/settings.go")
        runtime = self.read("gateway/internal/telemetry/runtime.go")
        self.assertIn('strings.HasPrefix(name, "OTEL_")', settings)
        self.assertIn('parsed.Scheme != "https"', settings)
        self.assertIn('parsed.Path != "/v1/traces"', settings)
        self.assertIn("speechidentity.LoadMTLSClient", runtime)
        self.assertIn("otlptracehttp.WithHTTPClient(client)", runtime)
        self.assertIn("sdktrace.ParentBased", runtime)
        self.assertNotIn("otel.SetTracerProvider", runtime)

    def test_deployment_keeps_seven_workloads_and_isolates_collector_egress(self) -> None:
        deployment = self.read("tools/kubernetes_deployment.py")
        profile = self.read("deployment/kubernetes-deployment-profile.example.json")
        for name in (
            "telemetry-ca.pem", "telemetry-client.crt", "telemetry-client.key",
            "TELEMETRY_OTLP_TRACES_ENDPOINT", "TELEMETRY_DEPLOYMENT_ID",
        ):
            self.assertIn(name, deployment)
        self.assertIn('rules.append({', deployment)
        self.assertIn('"ports": [_port(4318)]', deployment)
        self.assertIn('profile["telemetry"]["pod_selector"]', deployment)
        self.assertIn('"sample_ratio_ppm": 1000000', profile)


if __name__ == "__main__":
    unittest.main()
