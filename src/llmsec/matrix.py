from llmsec.catalog import ATTACKS_BY_ID, DEFENSE_COLUMNS_BY_ID, TARGETS_BY_ID
from llmsec.schemas import MatrixEstimateRequest, MatrixEstimateResponse


def estimate_matrix(request: MatrixEstimateRequest) -> MatrixEstimateResponse:
    unknown_targets = set(request.target_ids) - TARGETS_BY_ID.keys()
    unknown_attacks = set(request.attack_ids) - ATTACKS_BY_ID.keys()
    unknown_columns = set(request.defense_column_ids) - DEFENSE_COLUMNS_BY_ID.keys()
    if unknown_targets:
        raise ValueError(f"Unknown target IDs: {sorted(unknown_targets)}")
    if unknown_attacks:
        raise ValueError(f"Unknown attack IDs: {sorted(unknown_attacks)}")
    if unknown_columns:
        raise ValueError(f"Unknown defense column IDs: {sorted(unknown_columns)}")

    column_ids = list(dict.fromkeys(["baseline", *request.defense_column_ids]))
    valid_cells = 0
    skipped_cells = 0
    for target_id in request.target_ids:
        for attack_id in request.attack_ids:
            attack_applicable = target_id in ATTACKS_BY_ID[attack_id].applicable_target_ids
            for column_id in column_ids:
                defense_applicable = (
                    target_id in DEFENSE_COLUMNS_BY_ID[column_id].applicable_target_ids
                )
                if attack_applicable and defense_applicable:
                    valid_cells += len(request.model_ids)
                else:
                    skipped_cells += len(request.model_ids)

    trial_arms = valid_cells * request.trials
    return MatrixEstimateResponse(
        target_count=len(request.target_ids),
        attack_count=len(request.attack_ids),
        model_count=len(request.model_ids),
        defense_column_count=len(column_ids),
        matrix_cells=valid_cells,
        trial_arms=trial_arms,
        maximum_model_calls=trial_arms * request.max_turns,
        baseline_included=True,
        skipped_inapplicable_cells=skipped_cells,
    )
