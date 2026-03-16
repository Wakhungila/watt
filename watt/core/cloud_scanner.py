from __future__ import annotations

import re
import uuid

from watt.models.entities import Finding, FindingSeverity, NodeKind
from watt.modules.base import SimpleModule


class CloudScanModule(SimpleModule):
    """
    Detects cloud services based on hostnames.
    """

    name = "recon.cloud_scanner"
    phase = "recon"

    # Regex patterns for common cloud services
    CLOUD_PATTERNS = {
        "aws_s3": (re.compile(r"\.s3-?[a-z0-9-]+\.amazonaws\.com$|\.s3\.amazonaws\.com$"), "AWS S3 Bucket"),
        "aws_cloudfront": (re.compile(r"\.cloudfront\.net$"), "AWS CloudFront Distribution"),
        "aws_elb": (re.compile(r"\.elb\.amazonaws\.com$"), "AWS Elastic Load Balancer"),
        "azure_blob": (re.compile(r"\.blob\.core\.windows\.net$"), "Azure Blob Storage"),
        "azure_websites": (re.compile(r"\.azurewebsites\.net$"), "Azure App Service"),
        "gcp_storage": (re.compile(r"storage\.googleapis\.com$"), "GCP Cloud Storage"),
        "gcp_appengine": (re.compile(r"\.appspot\.com$"), "GCP App Engine"),
    }

    async def run(self) -> None:
        self.log.info("Scanning for cloud service patterns in hostnames...")
        hosts = self.ctx.map.nodes_by_kind(NodeKind.host)
        
        found_count = 0
        for host_node in hosts:
            for service_key, (pattern, service_name) in self.CLOUD_PATTERNS.items():
                if pattern.search(host_node.label):
                    found_count += 1
                    self.log.info("Detected %s for host: %s", service_name, host_node.label)
                    
                    # The existing upsert logic will merge tags and preserve higher confidence
                    self.ctx.map.upsert_node(
                        kind=NodeKind.host,
                        label=host_node.label,
                        confidence=host_node.confidence,
                        tags=["cloud", f"cloud:{service_key.split('_')[0]}"],
                    )

                    # Create a finding
                    self.ctx.map.add_finding(Finding(
                        id=str(uuid.uuid4()),
                        title=f"Cloud Service Detected: {service_name}",
                        summary=f"The host '{host_node.label}' matches a pattern for {service_name}.",
                        severity=FindingSeverity.info,
                        score=10.0,
                        tags=["cloud", "recon", service_key],
                        related_nodes=[host_node.id],
                        evidence=[],
                    ))
                    # A host can match multiple patterns, so we don't break here.
        
        self.log.info("Cloud scan complete. Found %d potential cloud services.", found_count)