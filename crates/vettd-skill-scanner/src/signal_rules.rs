//! Rule and method identifiers for first-party scanner signals.

pub(crate) const DECLARED_LICENSE: &str = "characteristics/declared-license";
pub(crate) const PRIMARY_LANGUAGE: &str = "characteristics/primary-language";
pub(crate) const STATIC_CONTEXT_TOKENS: &str = "performance/static-context-tokens";
pub(crate) const UNRESOLVABLE_INTERNAL_REFERENCES: &str =
    "reliability/unresolvable-internal-references";
pub(crate) const DECLARED_EXTERNAL_SERVICES: &str = "cost/declared-external-services";
pub(crate) const DECLARED_REQUIRED_ENV_VARS: &str = "cost/declared-required-env-vars";
pub(crate) const DECLARED_REQUIRED_TOOLS: &str = "compatibility/declared-required-tools";
pub(crate) const DECLARED_MCP_SERVERS: &str = "compatibility/declared-mcp-servers";
pub(crate) const DECLARED_HARNESS_TARGETS: &str = "compatibility/declared-harness-targets";
pub(crate) const DECLARED_ENVIRONMENT_ASSUMPTIONS: &str =
    "compatibility/declared-environment-assumptions";
pub(crate) const DECLARED_NAME: &str = "compatibility/declared-name";

// ── Reclassified non-safety rules (were VTD-0083, VTD-0102..0123 findings) ──
// Moved off the finding channel onto the signal channel under the slugs their
// substance belongs to (see the reclassify plan §3). Facts carry
// value_text + derivation "read"; measurements carry value_num + method;
// findings carry severity and emit only their failure branch.

// Characteristics — neutral attributes.
pub(crate) const REPOSITORY_LINK: &str = "characteristics/repository-link";
pub(crate) const EVAL_FILE_FORMAT: &str = "characteristics/eval-file-format";

// Performance.
pub(crate) const PROGRESSIVE_DISCLOSURE: &str = "performance/progressive-disclosure";

// Reliability — facts.
pub(crate) const GOTCHAS_SECTION: &str = "reliability/gotchas-section";
pub(crate) const EXAMPLES: &str = "reliability/examples";
pub(crate) const CHECKLIST_PATTERN: &str = "reliability/checklist-pattern";
pub(crate) const VALIDATION_LOOP: &str = "reliability/validation-loop";
pub(crate) const STEP_BY_STEP_WORKFLOW: &str = "reliability/step-by-step-workflow";
pub(crate) const DESCRIPTION_USAGE_CONTEXT: &str = "reliability/description-usage-context";
pub(crate) const EVAL_ASSERTIONS: &str = "reliability/eval-assertions";

// Reliability — findings (severity-bearing, failure branch only).
pub(crate) const GENERIC_INSTRUCTION: &str = "reliability/generic-instruction";
pub(crate) const DESCRIPTION_PRESENCE: &str = "reliability/description-presence";
pub(crate) const DESCRIPTION_BRIEFNESS: &str = "reliability/description-briefness";
pub(crate) const DESCRIPTION_OVERCLAIM: &str = "reliability/description-overclaim";
pub(crate) const EVAL_TEST_CASES_SUFFICIENT: &str = "reliability/eval-test-cases-sufficient";

// Reliability — measurements.
pub(crate) const EVAL_TEST_CASE_COUNT: &str = "reliability/eval-test-case-count";

// Cost — finding (VTD-0110 stays a severity-bearing finding per the plan §8.3).
pub(crate) const DESCRIPTION_LENGTH: &str = "cost/description-length";

// Compatibility — facts.
pub(crate) const CLI_HELP: &str = "compatibility/cli-help";
pub(crate) const STRUCTURED_OUTPUT: &str = "compatibility/structured-output";

// Compatibility — findings.
pub(crate) const INTERACTIVE_PROMPTS: &str = "compatibility/interactive-prompts";
pub(crate) const UNPINNED_DEPENDENCIES: &str = "compatibility/unpinned-dependencies";

pub(crate) const BUNDLE_EXTENSION_SHARE: &str = "bundle-extension-share";
pub(crate) const CL100K_SKILL_MD_BODY: &str = "tiktoken/cl100k_base/skill-md-body";
pub(crate) const EVAL_CASE_COUNT_METHOD: &str = "bundle-evals-case-count";
