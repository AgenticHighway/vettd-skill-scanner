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

pub(crate) const BUNDLE_EXTENSION_SHARE: &str = "bundle-extension-share";
pub(crate) const CL100K_SKILL_MD_BODY: &str = "tiktoken/cl100k_base/skill-md-body";
pub(crate) const FRONTMATTER_DECLARED_SERVICES: &str = "frontmatter-declared-services";
pub(crate) const FRONTMATTER_REQUIRED_ENV_VARS: &str = "frontmatter-required-env-vars";
pub(crate) const FRONTMATTER_ALLOWED_TOOLS: &str = "frontmatter-allowed-tools";
pub(crate) const FRONTMATTER_MCP_DECLARATIONS: &str = "frontmatter-mcp-declarations";
pub(crate) const FRONTMATTER_HARNESS_DECLARATIONS: &str = "frontmatter-harness-declarations";
