# my_custom_provider.py

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes


# Import necessary exporters and processors here (e.g., OTLP, Console)

class CustomTracerProvider(TracerProvider):
    def __init__(self):
        # Initialize with specific resource attributes or configurations
        custom_resource = Resource.create({
            ResourceAttributes.SERVICE_NAME: "my-custom-service",
            "custom.attribute": "value"
        })
        super().__init__(resource=custom_resource)

        # Configure processors and exporters (example with ConsoleExporter)
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        self.add_span_processor(processor)

        print("CustomTracerProvider initialized and configured!")


# The OpenTelemetry auto-instrumentation looks for an entry point 
# that returns a configured provider instance.
def get_custom_tracer_provider():
    return CustomTracerProvider()
