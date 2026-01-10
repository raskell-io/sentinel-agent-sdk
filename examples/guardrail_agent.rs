//! Guardrail agent example for AI content safety.
//!
//! This example demonstrates a guardrail agent that:
//! - Detects prompt injection attempts in user input
//! - Detects PII (emails, phone numbers, SSN patterns)
//! - Returns structured detection results with confidence scores

use regex::Regex;
use sentinel_agent_sdk::prelude::*;
use sentinel_agent_sdk::{
    DetectionSeverity, GuardrailDetection, GuardrailInspectEvent, GuardrailInspectionType,
    GuardrailResponse,
};

struct GuardrailAgent {
    injection_patterns: Vec<(Regex, &'static str)>,
    pii_patterns: Vec<(Regex, &'static str, &'static str)>,
}

impl GuardrailAgent {
    fn new() -> Self {
        let injection_patterns = vec![
            (
                Regex::new(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)").unwrap(),
                "ignore_instructions",
            ),
            (
                Regex::new(r"(?i)disregard\s+(all\s+)?(previous|prior|above)").unwrap(),
                "disregard_previous",
            ),
            (
                Regex::new(r"(?i)you\s+are\s+now\s+(a|an|in)\s+").unwrap(),
                "role_switch",
            ),
            (
                Regex::new(r"(?i)pretend\s+(you('re|are)|to\s+be)").unwrap(),
                "pretend_role",
            ),
            (
                Regex::new(r"(?i)system\s*:\s*").unwrap(),
                "system_prompt_inject",
            ),
            (
                Regex::new(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>").unwrap(),
                "llama_format_inject",
            ),
            (
                Regex::new(r"<\|im_start\|>|<\|im_end\|>").unwrap(),
                "chatml_format_inject",
            ),
        ];

        let pii_patterns = vec![
            (
                Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
                "email",
                "Email address",
            ),
            (
                Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
                "phone",
                "Phone number",
            ),
            (
                Regex::new(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b").unwrap(),
                "ssn",
                "Social Security Number",
            ),
            (
                Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap(),
                "credit_card",
                "Credit card number",
            ),
        ];

        Self {
            injection_patterns,
            pii_patterns,
        }
    }

    fn detect_prompt_injection(&self, content: &str) -> GuardrailResponse {
        let mut response = GuardrailResponse::clean();

        for (pattern, category) in &self.injection_patterns {
            if let Some(m) = pattern.find(content) {
                let mut detection = GuardrailDetection {
                    category: format!("prompt_injection.{}", category),
                    description: format!(
                        "Potential prompt injection detected: {}",
                        category.replace('_', " ")
                    ),
                    severity: DetectionSeverity::High,
                    confidence: Some(0.85),
                    span: None,
                };
                detection.span = Some(sentinel_agent_sdk::TextSpan {
                    start: m.start(),
                    end: m.end(),
                });
                response.add_detection(detection);
            }
        }

        response
    }

    fn detect_pii(&self, content: &str) -> GuardrailResponse {
        let mut response = GuardrailResponse::clean();
        let mut redacted = content.to_string();

        for (pattern, category, description) in &self.pii_patterns {
            for m in pattern.find_iter(content) {
                let mut detection = GuardrailDetection {
                    category: format!("pii.{}", category),
                    description: format!("{} detected", description),
                    severity: DetectionSeverity::Medium,
                    confidence: Some(0.95),
                    span: None,
                };
                detection.span = Some(sentinel_agent_sdk::TextSpan {
                    start: m.start(),
                    end: m.end(),
                });
                response.add_detection(detection);
                redacted = redacted.replace(m.as_str(), &format!("[REDACTED_{}]", category.to_uppercase()));
            }
        }

        if response.detected {
            response.redacted_content = Some(redacted);
        }

        response
    }
}

#[async_trait]
impl Agent for GuardrailAgent {
    fn name(&self) -> &str {
        "guardrail-agent"
    }

    async fn on_request(&self, _request: &Request) -> Decision {
        // Allow all requests - guardrail inspection happens via on_guardrail_inspect
        Decision::allow()
    }

    async fn on_guardrail_inspect(&self, event: &GuardrailInspectEvent) -> GuardrailResponse {
        match event.inspection_type {
            GuardrailInspectionType::PromptInjection => self.detect_prompt_injection(&event.content),
            GuardrailInspectionType::PiiDetection => self.detect_pii(&event.content),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    AgentRunner::new(GuardrailAgent::new())
        .with_name("guardrail-agent")
        .with_socket("/tmp/guardrail-agent.sock")
        .run()
        .await
}
