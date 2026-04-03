from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class PlaceholderTokensConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    banned_tokens: list[str] = Field(
        default_factory=lambda: ["TODO", "FIXME", "HACK", "TEMPORARY"]
    )


class BoundaryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_glob: str
    forbidden_prefixes: list[str] = Field(default_factory=list)
    message: str = "Forbidden import edge."


class ForbiddenImportEdgesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    boundaries: list[BoundaryConfig] = Field(default_factory=list)


class StubFunctionBodyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    excluded_function_patterns: list[str] = Field(
        default_factory=lambda: ["__init__", "setUp", "tearDown", "setUpClass", "tearDownClass"]
    )


class AiInstructionCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class BareExceptPassConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AiConversationalBleedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AiIdentityRefusalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class HallucinatedPlaceholderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    extra_patterns: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(
        default_factory=lambda: ["example.com", "example.org", "example.net"]
    )


class DeadCodeCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    min_consecutive_lines: int = 4
    excluded_paths: list[str] = Field(
        default_factory=lambda: ["docs/**", "examples/**", "*.md"]
    )


class IncompleteErrorMessageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class MissingDefaultBranchConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 60% precision, fires on guard clauses
    min_elif_count: int = 2
    check_match: bool = True


class AiHardcodedMocksConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 50% precision without per-project tuning
    additional_excluded_paths: list[str] = Field(
        default_factory=lambda: ["**/seed*", "**/conftest*", "**/factory*", "**/fake*"]
    )


class UndeclaredImportConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: too noisy without per-project manifest config
    additional_allowed: list[str] = Field(
        default_factory=lambda: ["typing", "typing_extensions"]
    )


class SqlStringConcatConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class InsecureDefaultConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class HardcodedSecretConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class TypescriptAnyAbuseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ReactIndexKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ReactAsyncUseeffectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class GoIgnoredErrorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    extra_allowed_patterns: list[str] = Field(default_factory=list)


class PythonMutableDefaultConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class GoMissingDeferConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ConsoleLogConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    allowed_methods: list[str] = Field(default_factory=lambda: ["error"])


class GoErrorWrapConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class CrossLanguageIdiomConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsAwaitInLoopConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsJsonParseUnguardedConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsUnhandledPromiseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsTimerNoCleanupConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsLooseEqualityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class JsDangerouslySetHtmlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DeepNestingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 243K findings at depth=4 is too noisy
    max_depth: int = 6


class LargeFunctionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 16K findings at 60 lines is too noisy
    max_lines: int = 100


class SelectStarSqlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class WeakHashConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class RegexDosConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ObviousPerfDrainConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: 37K findings is too noisy without scope analysis


class ObfuscatedCodeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class GlobalStateLeakConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class CollectionModifyWhileIteratingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class DivisionByZeroRiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False


class UnreachableCodeAfterReturnConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ParamReassignmentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: noisy without project-specific tuning


class LargeFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in
    max_lines: int = 500


class ShortVariableNameConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: noisy
    min_length: int = 2
    allowed: list[str] = Field(
        default_factory=lambda: ["i", "j", "k", "x", "y", "z", "_", "e"]
    )


class GotoUsageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AssignmentInConditionalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class WithinFileDuplicationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    min_lines: int = 4


class EarlyReturnOpportunityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in: style opinion


class RecursionWithoutLimitConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: many false positives


class DeepInheritanceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in


class LargeAnonymousFunctionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in
    max_lines: int = 20


class DebugCodeLeftConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class StaleCommentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False  # Opt-in: very noisy


class ContradictoryNullCheckConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class LockWithoutReleaseConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class IdorRiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True  # Opt-in low-confidence; enabled by default for awareness


class ThreadUnsafeGlobalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ManyPositionalArgsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_positional: int = 4


class RedundantSqlIndexConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class UseAfterFreeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class WeakFunctionNameConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class MultipleClassesPerFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class OversizedClassConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_methods: int = 10


class BreakInNestedLoopConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DangerousShellInMarkdownConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class RulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    placeholder_tokens: PlaceholderTokensConfig = Field(default_factory=PlaceholderTokensConfig)
    forbidden_import_edges: ForbiddenImportEdgesConfig = Field(
        default_factory=ForbiddenImportEdgesConfig
    )
    stub_function_body: StubFunctionBodyConfig = Field(
        default_factory=StubFunctionBodyConfig
    )
    ai_instruction_comment: AiInstructionCommentConfig = Field(
        default_factory=AiInstructionCommentConfig
    )
    bare_except_pass: BareExceptPassConfig = Field(default_factory=BareExceptPassConfig)
    ai_conversational_bleed: AiConversationalBleedConfig = Field(
        default_factory=AiConversationalBleedConfig
    )
    ai_identity_refusal: AiIdentityRefusalConfig = Field(
        default_factory=AiIdentityRefusalConfig
    )
    hallucinated_placeholder: HallucinatedPlaceholderConfig = Field(
        default_factory=HallucinatedPlaceholderConfig
    )
    dead_code_comment: DeadCodeCommentConfig = Field(default_factory=DeadCodeCommentConfig)
    incomplete_error_message: IncompleteErrorMessageConfig = Field(
        default_factory=IncompleteErrorMessageConfig
    )
    missing_default_branch: MissingDefaultBranchConfig = Field(
        default_factory=MissingDefaultBranchConfig
    )
    ai_hardcoded_mocks: AiHardcodedMocksConfig = Field(
        default_factory=AiHardcodedMocksConfig
    )
    undeclared_import: UndeclaredImportConfig = Field(default_factory=UndeclaredImportConfig)
    sql_string_concat: SqlStringConcatConfig = Field(default_factory=SqlStringConcatConfig)
    insecure_default: InsecureDefaultConfig = Field(default_factory=InsecureDefaultConfig)
    hardcoded_secret: HardcodedSecretConfig = Field(default_factory=HardcodedSecretConfig)
    typescript_any_abuse: TypescriptAnyAbuseConfig = Field(
        default_factory=TypescriptAnyAbuseConfig
    )
    react_index_key: ReactIndexKeyConfig = Field(default_factory=ReactIndexKeyConfig)
    react_async_useeffect: ReactAsyncUseeffectConfig = Field(
        default_factory=ReactAsyncUseeffectConfig
    )
    go_ignored_error: GoIgnoredErrorConfig = Field(default_factory=GoIgnoredErrorConfig)
    python_mutable_default: PythonMutableDefaultConfig = Field(
        default_factory=PythonMutableDefaultConfig
    )
    go_missing_defer: GoMissingDeferConfig = Field(default_factory=GoMissingDeferConfig)
    console_log_in_production: ConsoleLogConfig = Field(default_factory=ConsoleLogConfig)
    go_error_wrap_missing_w: GoErrorWrapConfig = Field(default_factory=GoErrorWrapConfig)
    cross_language_idiom: CrossLanguageIdiomConfig = Field(
        default_factory=CrossLanguageIdiomConfig
    )
    js_await_in_loop: JsAwaitInLoopConfig = Field(default_factory=JsAwaitInLoopConfig)
    js_json_parse_unguarded: JsJsonParseUnguardedConfig = Field(
        default_factory=JsJsonParseUnguardedConfig
    )
    js_unhandled_promise: JsUnhandledPromiseConfig = Field(
        default_factory=JsUnhandledPromiseConfig
    )
    js_timer_no_cleanup: JsTimerNoCleanupConfig = Field(default_factory=JsTimerNoCleanupConfig)
    js_loose_equality: JsLooseEqualityConfig = Field(default_factory=JsLooseEqualityConfig)
    js_dangerously_set_html: JsDangerouslySetHtmlConfig = Field(
        default_factory=JsDangerouslySetHtmlConfig
    )
    deep_nesting: DeepNestingConfig = Field(default_factory=DeepNestingConfig)
    large_function: LargeFunctionConfig = Field(default_factory=LargeFunctionConfig)
    select_star_sql: SelectStarSqlConfig = Field(default_factory=SelectStarSqlConfig)
    weak_hash: WeakHashConfig = Field(default_factory=WeakHashConfig)
    regex_dos: RegexDosConfig = Field(default_factory=RegexDosConfig)
    obvious_perf_drain: ObviousPerfDrainConfig = Field(default_factory=ObviousPerfDrainConfig)
    obfuscated_code: ObfuscatedCodeConfig = Field(default_factory=ObfuscatedCodeConfig)
    global_state_leak: GlobalStateLeakConfig = Field(default_factory=GlobalStateLeakConfig)
    collection_modify_while_iterating: CollectionModifyWhileIteratingConfig = Field(
        default_factory=CollectionModifyWhileIteratingConfig
    )
    division_by_zero_risk: DivisionByZeroRiskConfig = Field(
        default_factory=DivisionByZeroRiskConfig
    )
    unreachable_code_after_return: UnreachableCodeAfterReturnConfig = Field(
        default_factory=UnreachableCodeAfterReturnConfig
    )
    param_reassignment: ParamReassignmentConfig = Field(
        default_factory=ParamReassignmentConfig
    )
    large_file: LargeFileConfig = Field(default_factory=LargeFileConfig)
    short_variable_name: ShortVariableNameConfig = Field(
        default_factory=ShortVariableNameConfig
    )
    goto_usage: GotoUsageConfig = Field(default_factory=GotoUsageConfig)
    assignment_in_conditional: AssignmentInConditionalConfig = Field(
        default_factory=AssignmentInConditionalConfig
    )
    within_file_duplication: WithinFileDuplicationConfig = Field(
        default_factory=WithinFileDuplicationConfig
    )
    early_return_opportunity: EarlyReturnOpportunityConfig = Field(
        default_factory=EarlyReturnOpportunityConfig
    )
    recursion_without_limit: RecursionWithoutLimitConfig = Field(
        default_factory=RecursionWithoutLimitConfig
    )
    deep_inheritance: DeepInheritanceConfig = Field(default_factory=DeepInheritanceConfig)
    large_anonymous_function: LargeAnonymousFunctionConfig = Field(
        default_factory=LargeAnonymousFunctionConfig
    )
    debug_code_left: DebugCodeLeftConfig = Field(default_factory=DebugCodeLeftConfig)
    stale_comment: StaleCommentConfig = Field(default_factory=StaleCommentConfig)
    contradictory_null_check: ContradictoryNullCheckConfig = Field(
        default_factory=ContradictoryNullCheckConfig
    )
    lock_without_release: LockWithoutReleaseConfig = Field(
        default_factory=LockWithoutReleaseConfig
    )
    idor_risk: IdorRiskConfig = Field(default_factory=IdorRiskConfig)
    thread_unsafe_global: ThreadUnsafeGlobalConfig = Field(
        default_factory=ThreadUnsafeGlobalConfig
    )
    many_positional_args: ManyPositionalArgsConfig = Field(
        default_factory=ManyPositionalArgsConfig
    )
    redundant_sql_index: RedundantSqlIndexConfig = Field(
        default_factory=RedundantSqlIndexConfig
    )
    use_after_free: UseAfterFreeConfig = Field(default_factory=UseAfterFreeConfig)
    weak_function_name: WeakFunctionNameConfig = Field(
        default_factory=WeakFunctionNameConfig
    )
    multiple_classes_per_file: MultipleClassesPerFileConfig = Field(
        default_factory=MultipleClassesPerFileConfig
    )
    oversized_class: OversizedClassConfig = Field(default_factory=OversizedClassConfig)
    break_in_nested_loop: BreakInNestedLoopConfig = Field(
        default_factory=BreakInNestedLoopConfig
    )
    dangerous_shell_in_markdown: DangerousShellInMarkdownConfig = Field(
        default_factory=DangerousShellInMarkdownConfig
    )


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ignored_paths: list[str] = Field(
        default_factory=lambda: [
            # Version control & environments
            ".git/**", ".venv/**", "**/.venv/**",
            # Build outputs
            "dist/**", "**/dist/**",
            "build/**", "**/build/**",
            ".next/**", "**/.next/**",
            # Dependencies
            "node_modules/**", "**/node_modules/**",
            "vendor/**", "**/vendor/**",
            # Generated code
            "**/generated/**",
            # Agent/CI artifacts
            "**/.claude/**", "**/worktrees/**",
            "**/swarm/runs/**", "**/agents/swarm/**",
        ]
    )
    rules: RulesConfig = Field(default_factory=RulesConfig)


def resolve_config_path(repo_root: Path, explicit_path: Path | None) -> Path | None:
    if explicit_path is not None:
        return explicit_path

    candidates = [
        repo_root / ".slopcheck" / "config.yaml",
        repo_root / ".slopcheck.yaml",
        repo_root / ".slopcheck.yml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def load_config(repo_root: Path, explicit_path: Path | None = None) -> AppConfig:
    config_path = resolve_config_path(repo_root, explicit_path)
    if config_path is None:
        return AppConfig()

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise SystemExit(f"slopcheck: invalid YAML in {config_path}: {exc}") from exc

    try:
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise SystemExit(f"slopcheck: invalid config in {config_path}:\n{exc}") from exc
