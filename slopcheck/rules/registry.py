from __future__ import annotations

from slopcheck.rules.base import Rule
from slopcheck.rules.generic.ai_conversational_bleed import AiConversationalBleedRule
from slopcheck.rules.generic.ai_hardcoded_mocks import AiHardcodedMocksRule
from slopcheck.rules.generic.ai_identity_refusal import AiIdentityRefusalRule
from slopcheck.rules.generic.ai_instruction_comment import AiInstructionCommentRule
from slopcheck.rules.generic.assignment_in_conditional import AssignmentInConditionalRule
from slopcheck.rules.generic.bare_except_pass import BareExceptPassRule
from slopcheck.rules.generic.bare_except_pass_go import BareExceptPassGoRule
from slopcheck.rules.generic.bare_except_pass_js import BareExceptPassJsRule
from slopcheck.rules.generic.collection_modify_while_iterating import (
    CollectionModifyWhileIteratingRule,
)
from slopcheck.rules.generic.console_log_in_production import ConsoleLogInProductionRule
from slopcheck.rules.generic.cross_language_idiom import CrossLanguageIdiomRule
from slopcheck.rules.generic.dead_code_comment import DeadCodeCommentRule
from slopcheck.rules.generic.debug_code_left import DebugCodeLeftRule
from slopcheck.rules.generic.deep_inheritance import DeepInheritanceRule
from slopcheck.rules.generic.deep_nesting import DeepNestingRule
from slopcheck.rules.generic.division_by_zero_risk import DivisionByZeroRiskRule
from slopcheck.rules.generic.early_return_opportunity import EarlyReturnOpportunityRule
from slopcheck.rules.generic.global_state_leak import GlobalStateLeakRule
from slopcheck.rules.generic.go_error_wrap_missing_w import GoErrorWrapMissingWRule
from slopcheck.rules.generic.go_ignored_error import GoIgnoredErrorRule
from slopcheck.rules.generic.go_missing_defer import GoMissingDeferRule
from slopcheck.rules.generic.goto_usage import GotoUsageRule
from slopcheck.rules.generic.hallucinated_placeholder import HallucinatedPlaceholderRule
from slopcheck.rules.generic.hardcoded_secret import HardcodedSecretRule
from slopcheck.rules.generic.incomplete_error_message import IncompleteErrorMessageRule
from slopcheck.rules.generic.insecure_default import InsecureDefaultRule
from slopcheck.rules.generic.js_await_in_loop import JsAwaitInLoopRule
from slopcheck.rules.generic.js_dangerously_set_html import JsDangerouslySetHtmlRule
from slopcheck.rules.generic.js_json_parse_unguarded import JsJsonParseUnguardedRule
from slopcheck.rules.generic.js_loose_equality import JsLooseEqualityRule
from slopcheck.rules.generic.js_timer_no_cleanup import JsTimerNoCleanupRule
from slopcheck.rules.generic.js_unhandled_promise import JsUnhandledPromiseRule
from slopcheck.rules.generic.large_anonymous_function import LargeAnonymousFunctionRule
from slopcheck.rules.generic.large_file import LargeFileRule
from slopcheck.rules.generic.large_function import LargeFunctionRule
from slopcheck.rules.generic.missing_default_branch import MissingDefaultBranchRule
from slopcheck.rules.generic.obfuscated_code import ObfuscatedCodeRule
from slopcheck.rules.generic.obvious_perf_drain import ObviousPerfDrainRule
from slopcheck.rules.generic.param_reassignment import ParamReassignmentRule
from slopcheck.rules.generic.placeholder_tokens import PlaceholderTokensRule
from slopcheck.rules.generic.python_mutable_default import PythonMutableDefaultRule
from slopcheck.rules.generic.react_async_useeffect import ReactAsyncUseeffectRule
from slopcheck.rules.generic.react_index_key import ReactIndexKeyRule
from slopcheck.rules.generic.recursion_without_limit import RecursionWithoutLimitRule
from slopcheck.rules.generic.regex_dos import RegexDosRule
from slopcheck.rules.generic.select_star_sql import SelectStarSqlRule
from slopcheck.rules.generic.short_variable_name import ShortVariableNameRule
from slopcheck.rules.generic.sql_string_concat import SqlStringConcatRule
from slopcheck.rules.generic.stale_comment import StaleCommentRule
from slopcheck.rules.generic.stub_function_body import StubFunctionBodyRule
from slopcheck.rules.generic.stub_function_body_go import StubFunctionBodyGoRule
from slopcheck.rules.generic.stub_function_body_js import StubFunctionBodyJsRule
from slopcheck.rules.generic.typescript_any_abuse import TypescriptAnyAbuseRule
from slopcheck.rules.generic.undeclared_import import UndeclaredImportRule
from slopcheck.rules.generic.unreachable_code_after_return import UnreachableCodeAfterReturnRule
from slopcheck.rules.generic.unused_suppression import UnusedSuppressionRule
from slopcheck.rules.generic.weak_hash import WeakHashRule
from slopcheck.rules.generic.within_file_duplication import WithinFileDuplicationRule
from slopcheck.rules.repo.forbidden_import_edges import ForbiddenImportEdgesRule


def build_rules() -> list[Rule]:
    return [
        # Original rules
        PlaceholderTokensRule(),
        ForbiddenImportEdgesRule(),
        # Tier 1: AI code failure detection
        StubFunctionBodyRule(),
        AiInstructionCommentRule(),
        BareExceptPassRule(),
        # Tier 2: Smoking guns
        AiConversationalBleedRule(),
        AiIdentityRefusalRule(),
        HallucinatedPlaceholderRule(),
        # Tier 3: Supplementary
        DeadCodeCommentRule(),
        IncompleteErrorMessageRule(),
        MissingDefaultBranchRule(),
        AiHardcodedMocksRule(),
        # Multi-language variants
        StubFunctionBodyJsRule(),
        StubFunctionBodyGoRule(),
        BareExceptPassJsRule(),
        BareExceptPassGoRule(),
        # Security rules (Phase 2)
        UndeclaredImportRule(),
        SqlStringConcatRule(),
        InsecureDefaultRule(),
        HardcodedSecretRule(),
        # Language-specific rules (Phase 3)
        TypescriptAnyAbuseRule(),
        ReactIndexKeyRule(),
        ReactAsyncUseeffectRule(),
        GoIgnoredErrorRule(),
        PythonMutableDefaultRule(),
        GoMissingDeferRule(),
        # Phase 4: Language-quality rules
        ConsoleLogInProductionRule(),
        GoErrorWrapMissingWRule(),
        CrossLanguageIdiomRule(),
        # Meta-rules
        UnusedSuppressionRule(),
        # Phase 5: JS/Node and cross-language rules
        JsAwaitInLoopRule(),
        JsJsonParseUnguardedRule(),
        JsUnhandledPromiseRule(),
        JsTimerNoCleanupRule(),
        JsLooseEqualityRule(),
        JsDangerouslySetHtmlRule(),
        DeepNestingRule(),
        LargeFunctionRule(),
        SelectStarSqlRule(),
        WeakHashRule(),
        RegexDosRule(),
        ObviousPerfDrainRule(),
        # Phase 6: Obfuscation, global state, iteration safety, numeric safety
        ObfuscatedCodeRule(),
        GlobalStateLeakRule(),
        CollectionModifyWhileIteratingRule(),
        DivisionByZeroRiskRule(),
        UnreachableCodeAfterReturnRule(),
        # Phase 7: Code quality and correctness
        ParamReassignmentRule(),
        LargeFileRule(),
        ShortVariableNameRule(),
        GotoUsageRule(),
        AssignmentInConditionalRule(),
        # Phase 8: Structure and design rules
        WithinFileDuplicationRule(),
        EarlyReturnOpportunityRule(),
        RecursionWithoutLimitRule(),
        DeepInheritanceRule(),
        LargeAnonymousFunctionRule(),
        # Phase 9: Debug and comment quality
        DebugCodeLeftRule(),
        StaleCommentRule(),
    ]
