from llmsec.catalog import DEFENSE_COLUMNS_BY_ID
from llmsec.defenses.access_control import PiiRowAccessControl, RagAccessControl
from llmsec.defenses.action_gate import CodingActionGate
from llmsec.defenses.base import Defense
from llmsec.defenses.hardening import RuleReinforcementHardening
from llmsec.defenses.output_filters import (
    ExactOutputFilter,
    LegacyFuzzyOutputFilter,
    SyntheticPiiOutputFilter,
    TransformationAwareOutputFilter,
)
from llmsec.defenses.pipeline import DefensePipeline
from llmsec.defenses.regex_filter import RegexInputFilter

IMPLEMENTED_DEFENSE_FACTORIES = {
    "hardening_rule_v1": RuleReinforcementHardening,
    "input_regex_v1": RegexInputFilter,
    "output_exact_v1": ExactOutputFilter,
    "output_fuzzy_legacy_v1": LegacyFuzzyOutputFilter,
    "output_recovery_v1": TransformationAwareOutputFilter,
    "output_pii_v1": SyntheticPiiOutputFilter,
    "access_rag_acl_v1": RagAccessControl,
    "access_pii_row_v1": PiiRowAccessControl,
    "human_gate_v1": CodingActionGate,
}


def resolve_defense_column(column_id: str) -> DefensePipeline:
    column = DEFENSE_COLUMNS_BY_ID.get(column_id)
    if column is None:
        raise ValueError(f"Unknown defense column: {column_id}")

    defenses: list[Defense] = []
    for variant_id in column.defense_variant_ids:
        factory = IMPLEMENTED_DEFENSE_FACTORIES.get(variant_id)
        if factory is None:
            raise NotImplementedError(
                f"Defense variant is catalogued but not executable: {variant_id}"
            )
        defenses.append(factory())
    return DefensePipeline(defenses)
