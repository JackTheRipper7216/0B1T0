from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_benign_benchmark_measures_fpr_and_utility_without_provider_key() -> None:
    response = client.post(
        "/api/v1/benchmarks/benign",
        json={
            "target_ids": ["chatbot"],
            "defense_column_ids": ["baseline", "single:input_regex_v1"],
        },
    )

    assert response.status_code == 200
    cells = {
        cell["defense_column_id"]: cell for cell in response.json()["cells"]
    }
    assert cells["baseline"]["false_positive_rate_percent"] == 0
    assert cells["baseline"]["utility_retention_percent"] == 100
    assert cells["single:input_regex_v1"]["false_positive_rate_percent"] == 50
    assert cells["single:input_regex_v1"]["utility_retention_percent"] == 50


def test_benign_benchmark_rejects_inapplicable_defense() -> None:
    response = client.post(
        "/api/v1/benchmarks/benign",
        json={
            "target_ids": ["coding"],
            "defense_column_ids": ["single:access_rag_acl_v1"],
        },
    )

    assert response.status_code == 422
