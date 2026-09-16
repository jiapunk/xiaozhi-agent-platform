package telemetry

import (
	"context"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"xiaozhi-agent-platform/gateway/internal/speechidentity"
)

const instrumentationName = "xiaozhi-agent-platform/telemetry"

type Runtime struct {
	enabled        bool
	service        string
	provider       trace.TracerProvider
	propagator     propagation.TextMapPropagator
	shutdown       func(context.Context) error
	exportFailures atomic.Uint64
	binding        speechidentity.Binding
}

func New(ctx context.Context, settings Settings) (*Runtime, error) {
	if err := validateSettings(settings); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !settings.Enabled {
		return &Runtime{service: settings.Service,
			provider:   trace.NewNoopTracerProvider(),
			propagator: propagation.TraceContext{}}, nil
	}
	client, binding, err := speechidentity.LoadMTLSClient(
		settings.IdentityFiles, settings.ExportTimeout)
	if err != nil {
		return nil, err
	}
	client.Timeout = settings.ExportTimeout
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(settings.Endpoint),
		otlptracehttp.WithHTTPClient(client))
	if err != nil {
		client.CloseIdleConnections()
		return nil, err
	}
	processor := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithMaxQueueSize(2048),
		sdktrace.WithMaxExportBatchSize(256),
		sdktrace.WithBatchTimeout(5*time.Second),
		sdktrace.WithExportTimeout(settings.ExportTimeout))
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(
			float64(settings.SampleRatioPPM)/1_000_000))),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", settings.Service),
			attribute.String("deployment.environment.name", "production"),
			attribute.String("xiaozhi.deployment.id", settings.DeploymentID))),
		sdktrace.WithSpanProcessor(processor))
	runtime := &Runtime{
		enabled: true, service: settings.Service, provider: provider,
		propagator: propagation.TraceContext{}, binding: binding,
	}
	runtime.shutdown = func(shutdownContext context.Context) error {
		defer client.CloseIdleConnections()
		return provider.Shutdown(shutdownContext)
	}
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		runtime.exportFailures.Add(1)
	}))
	return runtime, nil
}

func (runtime *Runtime) Enabled() bool {
	return runtime != nil && runtime.enabled
}

func (runtime *Runtime) ExportFailures() uint64 {
	if runtime == nil {
		return 0
	}
	return runtime.exportFailures.Load()
}

func (runtime *Runtime) CertificateBinding() speechidentity.Binding {
	if runtime == nil {
		return speechidentity.Binding{}
	}
	return runtime.binding
}

func (runtime *Runtime) Shutdown(ctx context.Context) error {
	if runtime == nil || runtime.shutdown == nil {
		return nil
	}
	return runtime.shutdown(ctx)
}

func (runtime *Runtime) tracer() trace.Tracer {
	if runtime == nil || runtime.provider == nil {
		return trace.NewNoopTracerProvider().Tracer(instrumentationName)
	}
	return runtime.provider.Tracer(instrumentationName)
}
