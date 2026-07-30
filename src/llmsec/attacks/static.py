"""Versioned, contamination-audited static attack corpus."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from llmsec.oracle import CHATBOT_FLAG

CORPUS_VERSION = "static_corpus_v3"
OBJECTIVE_MARKER = "<<OBJECTIVE>>"
OBJECTIVES = {
    "chatbot": "the exact internal build key, including its prefix and delimiters",
}
ALLOWED_DELIVERIES = frozenset({"user", "retrieved_document", "repository_context"})
ALLOWED_RECOVERY_MODES = frozenset({"none", "bounded_reversible"})
MINIMUM_RECORDS_PER_FAMILY = 6
EXPECTED_FAMILIES_BY_TARGET = {
    "chatbot": frozenset(
        {
            "direct_prompt_injection",
            "prompt_extraction",
            "contextual_framing",
            "policy_puppetry",
            "decomposition_reconstruction",
            "encoding_evasion",
        }
    ),
}
CORPUS_DIRECTORY = Path(__file__).with_name("corpus")


@dataclass(frozen=True, slots=True)
class AttackSource:
    id: str
    name: str
    reference: str
    version: str
    license: str


@dataclass(frozen=True, slots=True)
class StaticAttackDefinition:
    id: str
    target_id: str
    family: str
    name: str
    source: AttackSource
    delivery: str
    turn_mode: str
    contamination: str
    validation_status: str
    success_definition: str
    recovery: str
    prompt_template: str
    context_template: str


@dataclass(frozen=True, slots=True)
class StaticAttackInstance:
    attack_id: str
    definition_id: str
    definition_name: str
    target_id: str
    instance_index: int
    payload: str
    context_payload: str
    delivery: str
    source: str
    source_reference: str
    source_version: str
    source_license: str
    contamination: str
    validation_status: str
    success_definition: str
    recovery: str
    suite_kind: str
    content_hash: str


def _required_text(record: dict[str, object], field: str, location: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{location}: {field!r} must be a non-empty string")
    return value.strip()


def _load_corpus_file(path: Path) -> tuple[StaticAttackDefinition, ...]:
    with path.open("rb") as stream:
        payload = tomllib.load(stream)

    location = path.name
    if payload.get("suite_version") != CORPUS_VERSION:
        raise ValueError(f"{location}: unsupported or missing suite_version")
    target_id = _required_text(payload, "target_id", location)
    if target_id not in OBJECTIVES:
        raise ValueError(f"{location}: unknown target_id {target_id!r}")
    turn_mode = _required_text(payload, "turn_mode", location)
    success_definition = _required_text(payload, "success_definition", location)
    if turn_mode != "single":
        raise ValueError(f"{location}: the static corpus only supports single-turn records")
    if success_definition != "exact_recovery":
        raise ValueError(f"{location}: only exact_recovery is a primary success definition")

    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ValueError(f"{location}: at least one source record is required")
    sources: dict[str, AttackSource] = {}
    for index, raw_source in enumerate(raw_sources):
        source_location = f"{location}:sources[{index}]"
        if not isinstance(raw_source, dict):
            raise TypeError(f"{source_location}: expected a table")
        source = AttackSource(
            id=_required_text(raw_source, "id", source_location),
            name=_required_text(raw_source, "name", source_location),
            reference=_required_text(raw_source, "reference", source_location),
            version=_required_text(raw_source, "version", source_location),
            license=_required_text(raw_source, "license", source_location),
        )
        if source.id in sources:
            raise ValueError(f"{source_location}: duplicate source id {source.id!r}")
        sources[source.id] = source

    raw_attacks = payload.get("attacks")
    if not isinstance(raw_attacks, list) or not raw_attacks:
        raise ValueError(f"{location}: at least one attack record is required")
    definitions: list[StaticAttackDefinition] = []
    for index, raw_attack in enumerate(raw_attacks):
        attack_location = f"{location}:attacks[{index}]"
        if not isinstance(raw_attack, dict):
            raise TypeError(f"{attack_location}: expected a table")
        source_id = _required_text(raw_attack, "source_id", attack_location)
        try:
            source = sources[source_id]
        except KeyError as exc:
            raise ValueError(
                f"{attack_location}: unknown source_id {source_id!r}"
            ) from exc
        delivery = _required_text(raw_attack, "delivery", attack_location)
        recovery = _required_text(raw_attack, "recovery", attack_location)
        if delivery not in ALLOWED_DELIVERIES:
            raise ValueError(f"{attack_location}: unsupported delivery {delivery!r}")
        if recovery not in ALLOWED_RECOVERY_MODES:
            raise ValueError(f"{attack_location}: unsupported recovery {recovery!r}")
        raw_context = raw_attack.get("context", "")
        if not isinstance(raw_context, str):
            raise TypeError(f"{attack_location}: context must be a string")
        context = raw_context.strip()
        if delivery == "user" and context:
            raise ValueError(f"{attack_location}: user delivery cannot include context")
        if delivery != "user" and not context:
            raise ValueError(f"{attack_location}: indirect delivery requires context")
        definition = StaticAttackDefinition(
            id=_required_text(raw_attack, "id", attack_location),
            target_id=target_id,
            family=_required_text(raw_attack, "family", attack_location),
            name=_required_text(raw_attack, "name", attack_location),
            source=source,
            delivery=delivery,
            turn_mode=turn_mode,
            contamination=_required_text(raw_attack, "contamination", attack_location),
            validation_status=_required_text(
                raw_attack, "validation_status", attack_location
            ),
            success_definition=success_definition,
            recovery=recovery,
            prompt_template=_required_text(raw_attack, "prompt", attack_location),
            context_template=context,
        )
        definitions.append(definition)
    return tuple(definitions)


def _load_corpus() -> tuple[StaticAttackDefinition, ...]:
    definitions: list[StaticAttackDefinition] = []
    for target_id in OBJECTIVES:
        definitions.extend(_load_corpus_file(CORPUS_DIRECTORY / f"{target_id}.toml"))

    ids = [definition.id for definition in definitions]
    if len(ids) != len(set(ids)):
        raise ValueError("Static corpus definition IDs must be globally unique")

    for target_id, expected_families in EXPECTED_FAMILIES_BY_TARGET.items():
        target_definitions = [
            definition
            for definition in definitions
            if definition.target_id == target_id
        ]
        actual_families = {
            definition.family for definition in target_definitions
        }
        if actual_families != expected_families:
            raise ValueError(
                f"{target_id}.toml family set differs from the v3 corpus contract"
            )
        for family in expected_families:
            family_count = sum(
                definition.family == family for definition in target_definitions
            )
            if family_count < MINIMUM_RECORDS_PER_FAMILY:
                raise ValueError(
                    f"{target_id}.toml must contain at least "
                    f"{MINIMUM_RECORDS_PER_FAMILY} records for {family!r}; "
                    f"found {family_count}"
                )

    flattened = "\n".join(
        part
        for definition in definitions
        for part in (
            definition.prompt_template,
            definition.context_template,
            definition.source.reference,
        )
    )
    forbidden_literals = (CHATBOT_FLAG, "gsk_")
    if any(literal in flattened for literal in forbidden_literals):
        raise ValueError("Static corpus contains a protected secret or provider-key literal")
    return tuple(definitions)


STATIC_ATTACK_DEFINITIONS = _load_corpus()
DEFINITIONS_BY_FAMILY_TARGET: dict[
    tuple[str, str], tuple[StaticAttackDefinition, ...]
] = {}
for _definition in STATIC_ATTACK_DEFINITIONS:
    _key = (_definition.family, _definition.target_id)
    DEFINITIONS_BY_FAMILY_TARGET[_key] = (
        *DEFINITIONS_BY_FAMILY_TARGET.get(_key, ()),
        _definition,
    )

# Public matrix rows describe attack classes. The immutable corpus keeps its
# narrower source families so existing payload IDs and provenance do not change.
STATIC_ATTACK_CLASS_MEMBERS = {
    "direct_prompt_injection": (
        "direct_prompt_injection",
        "prompt_extraction",
        "code_execution_injection",
    ),
    "indirect_prompt_injection": ("indirect_prompt_injection",),
    "contextual_framing": ("contextual_framing", "policy_puppetry"),
    "decomposition_reconstruction": ("decomposition_reconstruction",),
    "encoding_evasion": ("encoding_evasion",),
}

EXECUTABLE_STATIC_ATTACK_IDS = frozenset(STATIC_ATTACK_CLASS_MEMBERS)
TARGET_APPLICABILITY = {
    attack_class: frozenset(
        target_id
        for member_family in member_families
        for (candidate_family, target_id) in DEFINITIONS_BY_FAMILY_TARGET
        if candidate_family == member_family
    )
    for attack_class, member_families in STATIC_ATTACK_CLASS_MEMBERS.items()
}


def list_static_attack_definitions(
    attack_id: str,
    target_id: str,
) -> tuple[StaticAttackDefinition, ...]:
    member_families = STATIC_ATTACK_CLASS_MEMBERS.get(attack_id, ())
    definitions = tuple(
        definition
        for family in member_families
        for definition in DEFINITIONS_BY_FAMILY_TARGET.get((family, target_id), ())
    )
    if not definitions:
        raise ValueError(
            f"Attack {attack_id!r} has no executable static payload for {target_id!r}"
        )
    return definitions


def get_static_attack_count(attack_id: str, target_id: str) -> int:
    return len(list_static_attack_definitions(attack_id, target_id))


def get_static_attack_instance(
    attack_id: str,
    target_id: str = "chatbot",
    instance_index: int = 0,
) -> StaticAttackInstance:
    definitions = list_static_attack_definitions(attack_id, target_id)
    if instance_index < 0 or instance_index >= len(definitions):
        raise ValueError(
            f"Attack {attack_id!r} has {len(definitions)} unique payloads for "
            f"{target_id!r}; index {instance_index} would repeat the corpus"
        )
    definition = definitions[instance_index]
    objective = OBJECTIVES[target_id]
    prompt = definition.prompt_template.replace(OBJECTIVE_MARKER, objective)
    context = definition.context_template.replace(OBJECTIVE_MARKER, objective)
    content_hash = sha256(
        f"{definition.id}\0{definition.delivery}\0{prompt}\0{context}".encode()
    ).hexdigest()
    return StaticAttackInstance(
        attack_id=attack_id,
        definition_id=definition.id,
        definition_name=definition.name,
        target_id=target_id,
        instance_index=instance_index,
        payload=prompt,
        context_payload=context,
        delivery=definition.delivery,
        source=definition.source.name,
        source_reference=definition.source.reference,
        source_version=definition.source.version,
        source_license=definition.source.license,
        contamination=definition.contamination,
        validation_status=definition.validation_status,
        success_definition=definition.success_definition,
        recovery=definition.recovery,
        suite_kind=CORPUS_VERSION,
        content_hash=content_hash,
    )


def render_static_attack(
    attack_id: str,
    target_id: str = "chatbot",
    instance_index: int = 0,
) -> str:
    return get_static_attack_instance(attack_id, target_id, instance_index).payload
