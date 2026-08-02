"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";

import {
  checkCredential,
  closeLabSession,
  createLabSession,
  deleteArchivedRun,
  deleteLabSession,
  estimateMatrix,
  exportArchivedRun,
  fetchArchivedRun,
  fetchCatalog,
  fetchCurrentUser,
  fetchLabSession,
  fetchLabSessions,
  fetchRunArchive,
  login,
  runAdaptiveMatrix,
  runBenignBenchmark,
  runStaticMatrix,
  sendLabMessage,
  setApiAuthToken,
  signup,
  submitLabCandidate,
} from "@/lib/api";
import type {
  AdaptiveRun,
  ArchivedRunDetail,
  ArchivedRunSummary,
  AuthSession,
  BenignBenchmark,
  Catalog,
  CredentialCheck,
  LabMessageResult,
  LabSession,
  LabSessionDetail,
  MatrixEstimate,
  MatrixRun,
  ProviderId,
  TargetId,
} from "@/lib/types";

function toggleValue<T>(items: T[], value: T): T[] {
  return items.includes(value) ? items.filter((item) => item !== value) : [...items, value];
}

function isMatrixRun(value: unknown): value is MatrixRun {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<MatrixRun>;
  return typeof candidate.run_id === "string"
    && typeof candidate.target_id === "string"
    && typeof candidate.total_arms === "number"
    && Array.isArray(candidate.cells)
    && Array.isArray(candidate.trials)
    && Boolean(candidate.budget && typeof candidate.budget === "object");
}

function archivedMatrixRun(run: ArchivedRunDetail): MatrixRun | null {
  return run.kind === "static" && isMatrixRun(run.result) ? run.result : null;
}

export function MatrixWorkspace() {
  const [auth, setAuth] = useState<AuthSession | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [catalogError, setCatalogError] = useState("");
  const [activeView, setActiveView] = useState<"matrix" | "attack-lab" | "runs">("matrix");
  const [targets, setTargets] = useState<TargetId[]>(["chatbot"]);
  const [attacks, setAttacks] = useState<string[]>([
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "contextual_framing",
    "decomposition_reconstruction",
    "encoding_evasion",
  ]);
  const [providers, setProviders] = useState<ProviderId[]>(["groq"]);
  const [labProvider, setLabProvider] = useState<ProviderId>("groq");
  const [models, setModels] = useState<Record<ProviderId, string>>({
    groq: "openai/gpt-oss-120b",
    openai: "gpt-5.6-terra",
    anthropic: "claude-sonnet-5",
  });
  const [credentials, setCredentials] = useState<Record<ProviderId, string>>({ groq: "", openai: "", anthropic: "" });
  const [credentialChecks, setCredentialChecks] = useState<Partial<Record<ProviderId, CredentialCheck>>>({});
  const [checkingProvider, setCheckingProvider] = useState<ProviderId | null>(null);
  const [columns, setColumns] = useState<string[]>([
    "baseline",
    "single:hardening_rule_v1",
    "single:input_regex_v1",
    "single:output_recovery_v1",
    "combo:d6_legacy",
  ]);
  const [maxTurns, setMaxTurns] = useState(6);
  const [temperature, setTemperature] = useState(0);
  const [estimate, setEstimate] = useState<MatrixEstimate | null>(null);
  const [estimateError, setEstimateError] = useState("");
  const [notice, setNotice] = useState("");
  const [matrixRun, setMatrixRun] = useState<MatrixRun | null>(null);
  const [matrixRunSource, setMatrixRunSource] = useState<"live" | "archive">("live");
  const [runningMatrix, setRunningMatrix] = useState(false);
  const [matrixRunError, setMatrixRunError] = useState("");
  const [archivedRuns, setArchivedRuns] = useState<ArchivedRunSummary[]>([]);
  const [archiveError, setArchiveError] = useState("");
  const [benignBenchmark, setBenignBenchmark] = useState<BenignBenchmark | null>(null);
  const [runningBenchmark, setRunningBenchmark] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const storedToken = window.localStorage.getItem("obito_access_token");
    if (!storedToken) {
      setAuthChecked(true);
      return () => controller.abort();
    }
    setApiAuthToken(storedToken);
    fetchCurrentUser(controller.signal)
      .then((payload) => {
        setAuth({ ...payload, access_token: storedToken });
        setAuthChecked(true);
      })
      .catch(() => {
        window.localStorage.removeItem("obito_access_token");
        setApiAuthToken(null);
        setAuth(null);
        setAuthChecked(true);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!auth) return;
    const controller = new AbortController();
    fetchCatalog(controller.signal)
      .then((payload) => {
        setCatalog(payload);
        setModels((current) => Object.fromEntries(
          payload.providers.map((provider) => [
            provider.id,
            provider.models.some((model) => model.id === current[provider.id])
              ? current[provider.id]
              : provider.default_model_id,
          ]),
        ) as Record<ProviderId, string>);
        setCatalogError("");
      })
      .catch((error: Error) => {
        if (error.name !== "AbortError") setCatalogError(error.message);
      });
    return () => controller.abort();
  }, [auth]);

  const modelIds = providers.map((providerId) => `${providerId}:${models[providerId]}`);
  const temperatureUnsupported = providers.some((providerId) => {
    const provider = catalog?.providers.find((item) => item.id === providerId);
    return provider?.models.find((model) => model.id === models[providerId])?.temperature_supported === false;
  });
  const selectedApplicableAttackIds = useMemo(
    () => catalog?.attacks
      .filter((attack) => (
        attacks.includes(attack.id)
        && attack.implementation_status === "executable"
        && attack.applicable_target_ids.some((targetId) => targets.includes(targetId))
      ))
      .map((attack) => attack.id) ?? [],
    [catalog, attacks, targets],
  );

  useEffect(() => {
    if (!catalog || !targets.length || !selectedApplicableAttackIds.length || !modelIds.length) {
      setEstimate(null);
      return;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      estimateMatrix(
        {
          target_ids: targets,
          attack_ids: selectedApplicableAttackIds,
          model_ids: modelIds,
          defense_column_ids: columns,
          trials: 1,
          max_turns: maxTurns,
        },
        controller.signal,
      )
        .then((payload) => {
          setEstimate(payload);
          setEstimateError("");
        })
        .catch((error: Error) => {
          if (error.name !== "AbortError") setEstimateError(error.message);
        });
    }, 180);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [catalog, targets, providers, models, columns, maxTurns, selectedApplicableAttackIds]);

  useEffect(() => {
    if (!auth) return;
    const controller = new AbortController();
    fetchRunArchive(controller.signal)
      .then((runs) => {
        setArchivedRuns(runs);
        setArchiveError("");
        const latestStatic = runs.find((run) => run.kind === "static");
        if (!latestStatic) return;
        void fetchArchivedRun(latestStatic.run_id)
          .then((detail) => {
            if (controller.signal.aborted) return;
            const restored = archivedMatrixRun(detail);
            if (restored) {
              setMatrixRun(restored);
              setMatrixRunSource("archive");
            }
          })
          .catch((error: Error) => {
            if (!controller.signal.aborted) setMatrixRunError(`Could not restore saved matrix: ${error.message}`);
          });
      })
      .catch((error: Error) => {
        if (error.name !== "AbortError") {
          setArchiveError(error.message);
          setMatrixRunError(`Could not restore saved matrix: ${error.message}`);
        }
      });
    return () => controller.abort();
  }, [auth]);

  const applicableAttacks = useMemo(
    () => catalog?.attacks.filter((attack) => (
      attack.implementation_status === "executable"
      && attack.applicable_target_ids.some((id) => targets.includes(id))
    )) ?? [],
    [catalog, targets],
  );

  const singleDefenses = useMemo(
    () => catalog?.defense_columns.filter(
      (column) => column.kind === "single"
        && column.applicable_target_ids.some((id) => targets.includes(id)),
    ) ?? [],
    [catalog, targets],
  );

  const combinations = useMemo(
    () => catalog?.defense_columns.filter(
      (column) => column.kind === "combination"
        && column.applicable_target_ids.some((id) => targets.includes(id))
        && column.defense_variant_ids.every(
          (id) => catalog.defense_variants.find((variant) => variant.id === id)?.implementation_status === "executable",
        ),
    ) ?? [],
    [catalog, targets],
  );

  const selectedDefenseColumns = useMemo(
    () => catalog?.defense_columns.filter((column) => columns.includes(column.id)) ?? [],
    [catalog, columns],
  );

  const executableStaticAttacks = useMemo(
    () => applicableAttacks.filter(
      (attack) => attacks.includes(attack.id)
        && attack.implementation_status === "executable",
    ),
    [applicableAttacks, attacks],
  );
  const staticColumnIds = useMemo(
    () => targets.length === 1
      ? columns.filter((columnId) => catalog?.defense_columns.find(
        (column) => column.id === columnId && column.applicable_target_ids.includes(targets[0]),
      ))
      : [],
    [catalog, columns, targets],
  );
  const staticPayloadCount = useMemo(
    () => targets.length === 1
      ? executableStaticAttacks.reduce(
        (total, attack) => total + (attack.payload_counts[targets[0]] ?? 0),
        0,
      )
      : 0,
    [executableStaticAttacks, targets],
  );
  const staticPlannedArms = targets.length === 1
    ? staticPayloadCount
      * modelIds.length
      * new Set(["baseline", ...staticColumnIds]).size
    : 0;
  const benchmarkColumnIds = useMemo(
    () => columns.filter((columnId) => {
      const column = catalog?.defense_columns.find((item) => item.id === columnId);
      return column && targets.every((targetId) => column.applicable_target_ids.includes(targetId))
        && column.defense_variant_ids.every(
          (id) => catalog?.defense_variants.find((variant) => variant.id === id)?.implementation_status === "executable",
        );
    }),
    [catalog, columns, targets],
  );

  const staticCorpusReady = targets.length === 1
    && executableStaticAttacks.length > 0
    && staticPayloadCount > 0
    && staticPlannedArms <= 384
    && providers.every((providerId) => {
      const provider = catalog?.providers.find((item) => item.id === providerId);
      return Boolean(credentials[providerId]) || Boolean(provider?.configured_from_env);
    });

  function toggleTarget(targetId: TargetId) {
    if (targets.includes(targetId) && targets.length === 1) return;
    setTargets(toggleValue(targets, targetId));
  }

  function toggleProvider(providerId: ProviderId) {
    if (providers.includes(providerId) && providers.length === 1) return;
    const nextProviders = toggleValue(providers, providerId);
    setProviders(nextProviders);
    if (!providers.includes(providerId)) {
      setLabProvider(providerId);
    } else if (labProvider === providerId) {
      setLabProvider(nextProviders[0]);
    }
  }

  function toggleColumn(columnId: string) {
    if (columnId === "baseline") return;
    setColumns(toggleValue(columns, columnId));
  }

  async function validateCredential(providerId: ProviderId) {
    const key = credentials[providerId];
    if (!key.trim()) return;
    setCheckingProvider(providerId);
    try {
      const result = await checkCredential(providerId, key);
      setCredentialChecks((current) => ({ ...current, [providerId]: result }));
    } catch (error) {
      setCredentialChecks((current) => ({
        ...current,
        [providerId]: {
          provider_id: providerId,
          accepted_format: false,
          masked_key: "",
          persisted: false,
          message: error instanceof Error ? error.message : "Credential check failed",
        },
      }));
    } finally {
      setCheckingProvider(null);
    }
  }

  async function runFullStaticCorpus() {
    if (!staticCorpusReady || runningMatrix) return;
    setRunningMatrix(true);
    setMatrixRunError("");
    try {
      const result = await runStaticMatrix({
        target_id: targets[0],
        attack_ids: executableStaticAttacks.map((attack) => attack.id),
        model_ids: modelIds,
        defense_column_ids: staticColumnIds,
        corpus_mode: "full",
        temperature,
        credentials: Object.fromEntries(
          providers
            .filter((providerId) => credentials[providerId])
            .map((providerId) => [providerId, credentials[providerId]]),
        ),
      });
      setMatrixRun(result);
      setMatrixRunSource("live");
      void fetchRunArchive()
        .then((runs) => {
          setArchivedRuns(runs);
          setArchiveError("");
        })
        .catch((error: Error) => setArchiveError(error.message));
      setNotice(`Static census completed: ${result.total_arms} paired arms.`);
      window.setTimeout(() => setNotice(""), 3600);
    } catch (error) {
      setMatrixRunError(error instanceof Error ? error.message : "Static matrix run failed");
    } finally {
      setRunningMatrix(false);
    }
  }

  async function runUtilityPreflight() {
    if (runningBenchmark || !benchmarkColumnIds.length) return;
    setRunningBenchmark(true);
    setMatrixRunError("");
    try {
      setBenignBenchmark(await runBenignBenchmark({
        target_ids: targets,
        defense_column_ids: benchmarkColumnIds,
      }));
    } catch (error) {
      setMatrixRunError(error instanceof Error ? error.message : "Benchmark failed");
    } finally {
      setRunningBenchmark(false);
    }
  }

  async function handleLogin(username: string, password: string) {
    const session = await login(username, password);
    activateSession(session);
  }

  async function handleSignup(username: string, password: string) {
    const session = await signup(username, password);
    activateSession(session);
  }

  function activateSession(session: AuthSession) {
    window.localStorage.setItem("obito_access_token", session.access_token);
    setApiAuthToken(session.access_token);
    setAuth(session);
    setCatalog(null);
  }

  function handleLogout() {
    window.localStorage.removeItem("obito_access_token");
    setApiAuthToken(null);
    setAuth(null);
    setCatalog(null);
    setArchivedRuns([]);
    setMatrixRun(null);
    setMatrixRunSource("live");
  }

  if (!authChecked) {
    return <main className="boot-state"><div className="loader" aria-label="Checking session" /></main>;
  }

  if (!auth) {
    return <LoginScreen onLogin={handleLogin} onSignup={handleSignup} />;
  }

  if (catalogError) {
    return (
      <main className="boot-state">
        <div className="boot-card">
          <span className="status-light error" />
          <h1>API unavailable</h1>
          <p>Start the FastAPI service on port 8000, then reload this page.</p>
          <code>npm run dev:api</code>
          <small>{catalogError}</small>
        </div>
      </main>
    );
  }

  if (!catalog) {
    return <main className="boot-state"><div className="loader" aria-label="Loading catalog" /></main>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-label="0B1T0">0B1T0</span>
          <div><strong>OBITO</strong><span>LLM security benchmark</span></div>
        </div>
        <div className="account-card">
          <span>{auth.role === "admin" ? "Admin account" : "Researcher account"}</span>
          <strong>{auth.username}</strong>
          <button onClick={handleLogout}>Sign out</button>
        </div>

        <div className="side-block">
          <div className="side-heading"><span>Applications</span><small>{targets.length} selected</small></div>
          <div className="target-list">
            {catalog.targets.map((target) => (
              <button
                className={`target-row ${targets.includes(target.id) ? "selected" : ""}`}
                key={target.id}
                onClick={() => toggleTarget(target.id)}
              >
                <span className="check-box">{targets.includes(target.id) ? "✓" : ""}</span>
                <span><strong>{target.name}</strong><small>{target.risk}</small></span>
              </button>
            ))}
          </div>
        </div>

        <div className="side-block compact-fields">
          <div className="side-heading"><span>Run controls</span></div>
          <label>Adaptive maximum turns<input type="number" min="1" max="50" value={maxTurns} onChange={(event) => setMaxTurns(Number(event.target.value))} /></label>
          <label>Temperature<div className="range-line"><input type="range" min="0" max="1" step="0.1" value={temperature} onChange={(event) => setTemperature(Number(event.target.value))} /><span>{temperature.toFixed(1)}</span></div>{temperatureUnsupported && <small>Omitted for selected Claude models</small>}</label>
        </div>

        <div className="system-ready"><span className="status-light" />Catalog API connected</div>
      </aside>

      <main className="main-area">
        <header className="workspace-head">
          <div><span className="overline">Research workspace</span><h1>Chatbot Defense Matrix</h1><p>Run Chatbot attacks against baseline, individual defenses and selected logical stacks.</p></div>
          <div className="head-stat"><strong>{catalog.metrics.length}</strong><span>metrics per cell</span></div>
        </header>

        <nav className="workspace-tabs">
          <button className={activeView === "matrix" ? "active" : ""} onClick={() => setActiveView("matrix")}>Matrix Builder</button>
          <button className={activeView === "attack-lab" ? "active" : ""} onClick={() => setActiveView("attack-lab")}>Attack Lab</button>
          <button className={activeView === "runs" ? "active" : ""} onClick={() => setActiveView("runs")}>Run History</button>
        </nav>

        {activeView === "matrix" ? (
          <div className="matrix-builder">
            <section className="builder-section providers-section">
              <div className="section-title"><span>01</span><div><h2>Model backends</h2><p>Select one or more providers for transfer testing. Keys remain in memory only.</p></div></div>
              <div className="provider-grid">
                {catalog.providers.map((provider) => {
                  const selected = providers.includes(provider.id);
                  const credentialResult = credentialChecks[provider.id];
                  return (
                    <article className={`provider ${selected ? "selected" : ""}`} key={provider.id}>
                      <button className="provider-toggle" onClick={() => toggleProvider(provider.id)}>
                        <span className="check-box">{selected ? "✓" : ""}</span>
                        <span><strong>{provider.name}</strong><small>{provider.product_label}</small></span>
                        {provider.configured_from_env && <em>ENV</em>}
                      </button>
                      {selected && (
                        <div className="provider-fields">
                          <label>Model<select value={models[provider.id]} onChange={(event) => setModels((current) => ({ ...current, [provider.id]: event.target.value }))}>{provider.models.map((model) => <option key={model.id} value={model.id}>{model.label}</option>)}</select></label>
                          <label>API key<div className="key-line"><input type="password" autoComplete="off" placeholder={provider.credential_placeholder} value={credentials[provider.id]} onChange={(event) => { setCredentials((current) => ({ ...current, [provider.id]: event.target.value })); setCredentialChecks((current) => ({ ...current, [provider.id]: undefined })); }} /><button disabled={!credentials[provider.id] || checkingProvider === provider.id} onClick={() => validateCredential(provider.id)}>{checkingProvider === provider.id ? "…" : "Check format"}</button></div></label>
                          {credentialResult && <p className={`key-result ${credentialResult.accepted_format ? "valid" : "invalid"}`}>{credentialResult.message}</p>}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
              <p className="provider-note">Groq hosts Llama and GPT-OSS. Proprietary GPT and Claude calls use their own providers.</p>
            </section>

            <section className="builder-section">
              <div className="section-title"><span>02</span><div><h2>Static attack classes</h2><p>The Chatbot supplies the objective; each selected class becomes a matrix row.</p></div></div>
              <div className="option-grid attacks-grid">
                {applicableAttacks.map((attack) => (
                  <button className={`option-button ${attacks.includes(attack.id) ? "selected" : ""}`} key={attack.id} onClick={() => setAttacks(toggleValue(attacks, attack.id))}>
                    <span className="check-box">{attacks.includes(attack.id) ? "✓" : ""}</span>
                    <span><strong>{attack.name}</strong><small>{targets.length === 1 ? `${attack.payload_counts[targets[0]] ?? 0} unique payloads` : "Static corpus"}</small></span>
                  </button>
                ))}
              </div>
            </section>

            <section className="builder-section">
              <div className="section-title"><span>03</span><div><h2>Five defense columns</h2><p>Baseline is mandatory. Each named defense is measured independently when applicable.</p></div></div>
              <div className="baseline-row"><span className="locked-check">✓</span><div><strong>Baseline</strong><small>No defenses · always included</small></div><span className="locked-label">Locked</span></div>
              <div className="option-grid">
                {singleDefenses.map((defense) => (
                  <button className={`option-button ${columns.includes(defense.id) ? "selected" : ""}`} key={defense.id} onClick={() => toggleColumn(defense.id)}>
                    <span className="check-box">{columns.includes(defense.id) ? "✓" : ""}</span>
                    <span><strong>{defense.name}</strong><small>Individual defense</small></span>
                  </button>
                ))}
              </div>
            </section>

            <section className="builder-section combinations-section">
              <div className="section-title"><span>04</span><div><h2>D6 combination</h2><p>The frozen proof-of-concept stack remains an additional comparison column.</p></div></div>
              <div className="option-grid">
                {combinations.map((combination) => (
                  <button className={`option-button ${columns.includes(combination.id) ? "selected" : ""}`} key={combination.id} onClick={() => toggleColumn(combination.id)}>
                    <span className="check-box">{columns.includes(combination.id) ? "✓" : ""}</span>
                    <span><strong>{combination.name}</strong><small>{combination.defense_variant_ids.length} defense layers</small></span>
                  </button>
                ))}
              </div>
            </section>

            <section className="builder-section preview-section">
              <div className="section-title"><span>05</span><div><h2>Matrix preview</h2><p>Planned cells are executed for every selected model and trial seed. Inapplicable intersections remain explicitly N/A.</p></div></div>
              <div className="matrix-previews">
                {targets.map((targetId) => {
                  const target = catalog.targets.find((item) => item.id === targetId)!;
                  const selectedAttackRows = catalog.attacks.filter((attack) => attacks.includes(attack.id));
                  return (
                    <div className="matrix-preview" key={targetId}>
                      <div className="preview-name"><strong>{target.name}</strong><span>{modelIds.length} model{modelIds.length === 1 ? "" : "s"}</span></div>
                      <div className="preview-scroll">
                        <table>
                          <thead><tr><th>Attack row</th>{selectedDefenseColumns.map((column) => <th key={column.id}>{column.name}</th>)}</tr></thead>
                          <tbody>
                            {selectedAttackRows.map((attack) => (
                              <tr key={attack.id}>
                                <td><strong>{attack.name}</strong><span>static corpus</span></td>
                                {selectedDefenseColumns.map((column) => {
                                  const applicable = attack.applicable_target_ids.includes(targetId) && column.applicable_target_ids.includes(targetId);
                                  return <td key={column.id}><span className={applicable ? "planned-cell" : "na-cell"}>{applicable ? "Planned" : "N/A"}</span></td>;
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="metric-strip">
              {catalog.metrics.map((metric) => <span key={metric.id}>{metric.name}</span>)}
            </section>

            <section className="benchmark-preflight">
              <div><span className="overline">No API calls</span><h3>Benign defense preflight</h3><p>Measure deterministic false positives and utility retention before spending provider budget.</p></div>
              <button disabled={runningBenchmark || !benchmarkColumnIds.length} onClick={() => void runUtilityPreflight()}>{runningBenchmark ? "Running…" : "Run benign preflight"}</button>
              {benignBenchmark && (
                <div className="benchmark-cells">
                  {benignBenchmark.cells.map((cell) => (
                    <article key={`${cell.target_id}:${cell.defense_column_id}`}>
                      <strong>{catalog.targets.find((target) => target.id === cell.target_id)?.name}</strong>
                      <span>{catalog.defense_columns.find((column) => column.id === cell.defense_column_id)?.name}</span>
                      <div><b>{cell.false_positive_rate_percent.toFixed(0)}%</b><small>FPR</small></div>
                      <div><b>{cell.utility_retention_percent.toFixed(0)}%</b><small>utility</small></div>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="launch-bar">
              <div className="launch-estimate">
                <div><strong>{estimate?.matrix_cells ?? "—"}</strong><span>matrix cells</span></div>
                <div><strong>{staticPayloadCount || "—"}</strong><span>corpus payloads</span></div>
                <div><strong>{staticPlannedArms || "—"}</strong><span>static census calls</span></div>
                {!!estimate?.skipped_inapplicable_cells && <div><strong>{estimate.skipped_inapplicable_cells}</strong><span>N/A cells skipped</span></div>}
              </div>
              <div className="launch-action">
                {(estimateError || matrixRunError) && <small>{estimateError || matrixRunError}</small>}
                {!staticCorpusReady && !estimateError && !matrixRunError && <small>{staticPlannedArms > 384 ? "This selection exceeds the 384-call safety limit; use one model or fewer defense columns." : "Select one application, at least one applicable static attack, and provide every selected provider key."}</small>}
                <button disabled={!estimate || !staticCorpusReady || runningMatrix} onClick={() => void runFullStaticCorpus()}>{runningMatrix ? "Running full static corpus…" : `Run full static corpus (${staticPayloadCount})`} <span>→</span></button>
              </div>
            </section>

            {matrixRun && (
              <section className="static-run-results" id="static-run-results">
                <header>
                  <div><span className="overline">{matrixRunSource === "archive" ? "Restored" : "Latest"} {matrixRun.status.replace("_", " ")} census</span><h2>Static attack matrix</h2><p>Matched protected value, immutable corpus record, model, and payload index across every completed baseline–defense pair.</p></div>
                  <div className="run-id"><span>Run</span><strong>{matrixRun.run_id.slice(0, 8)}</strong><small>{matrixRun.total_arms} arms · {matrixRun.budget.target_calls} calls</small></div>
                </header>
                <div className="static-results-table">
                  <table>
                    <thead><tr><th>Attack</th><th>Model</th><th>Defense</th><th>Result</th><th>ASR</th><th>Reduction</th><th>Latency</th><th>Tokens</th><th>Cost</th></tr></thead>
                    <tbody>
                      {matrixRun.cells.map((cell) => {
                        const attack = catalog.attacks.find((item) => item.id === cell.attack_id);
                        const defense = catalog.defense_columns.find((item) => item.id === cell.defense_column_id);
                        return (
                          <tr key={`${cell.attack_id}:${cell.model_id}:${cell.defense_column_id}`}>
                            <td><strong>{attack?.name ?? cell.attack_id}</strong></td>
                            <td>{cell.model_id}</td>
                            <td>{defense?.name ?? cell.defense_column_id}</td>
                            <td><span className={`matrix-outcome ${cell.success_count ? "success" : "failed"}`}>{cell.success_count ? "Success" : "Failed"}</span></td>
                            <td>{cell.asr_percent.toFixed(0)}% <small>({cell.asr_ci_low_percent.toFixed(0)}–{cell.asr_ci_high_percent.toFixed(0)})</small></td>
                            <td title={cell.asr_delta_ci_low_points === null ? "No complete baseline–defense pair" : `Defended minus baseline 95% CI: ${cell.asr_delta_ci_low_points.toFixed(1)} to ${cell.asr_delta_ci_high_points?.toFixed(1)} pp`}>{cell.asr_reduction_points.toFixed(0)} pp <small>n={cell.paired_sample_n}</small></td>
                            <td title="Median paired end-to-end latency overhead">{cell.median_latency_overhead_ms === null ? "—" : `${cell.median_latency_overhead_ms.toFixed(0)} ms`}</td>
                            <td>{cell.total_tokens}</td>
                            <td>{cell.estimated_cost_usd === null ? "—" : `$${cell.estimated_cost_usd.toFixed(5)}`}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="pilot-trace-head"><h3>Attack execution history</h3><span>Attacker-visible inputs and outputs only</span></div>
                <div className="pilot-traces">
                  {matrixRun.trials.map((trial, index) => {
                    const defense = catalog.defense_columns.find((item) => item.id === trial.defense_column_id);
                    return (
                      <article className={`pilot-trace ${trial.success ? "success" : "failed"}`} key={`${trial.attack_id}:${trial.model_id}:${trial.defense_column_id}:${index}`}>
                        <header><span>{defense?.name ?? trial.defense_column_id} · {trial.attack_definition_name}</span><strong>{trial.success ? "Success" : "Failed"}</strong></header>
                        <label>Attack input</label><p>{trial.attack_input}</p>
                        {trial.attack_context && <><label>Injected {trial.attack_delivery.replace("_", " ")}</label><p>{trial.attack_context}</p></>}
                        <label>Visible output</label><p>{trial.visible_output || "No visible output"}</p>
                        <footer><span>{trial.model_id}</span><span>{trial.attack_source}</span><span>{trial.input_tokens + trial.output_tokens} tokens</span>{trial.raw_model_disclosure && !trial.success && <span>Raw disclosure filtered</span>}</footer>
                      </article>
                    );
                  })}
                </div>
              </section>
            )}
          </div>
        ) : activeView === "attack-lab" ? (
          <AttackLab
            availableProviders={providers}
            catalog={catalog}
            credentials={credentials}
            modelSelections={models}
            selectedTarget={targets[0]}
            selectedProvider={providers.includes(labProvider) ? labProvider : providers[0]}
            selectedModel={models[providers.includes(labProvider) ? labProvider : providers[0]]}
            temperature={temperature}
            onProviderChange={setLabProvider}
          />
        ) : (
          <RunArchive runs={archivedRuns} error={archiveError} catalog={catalog} />
        )}
      </main>
      {notice && <div className="toast"><span className="status-light" />{notice}</div>}
    </div>
  );
}

function LoginScreen({
  onLogin,
  onSignup,
}: {
  onLogin: (username: string, password: string) => Promise<void>;
  onSignup: (username: string, password: string) => Promise<void>;
}) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirmation, setPasswordConfirmation] = useState("");
  const [loginError, setLoginError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!username.trim() || !password || submitting) return;
    if (mode === "signup" && password !== passwordConfirmation) {
      setLoginError("Passwords do not match");
      return;
    }
    setSubmitting(true);
    setLoginError("");
    try {
      if (mode === "signup") {
        await onSignup(username.trim(), password);
      } else {
        await onLogin(username.trim(), password);
      }
    } catch (error) {
      setLoginError(error instanceof Error ? error.message : "Authentication failed");
    } finally {
      setSubmitting(false);
    }
  }

  function switchMode(nextMode: "login" | "signup") {
    setMode(nextMode);
    setPassword("");
    setPasswordConfirmation("");
    setLoginError("");
  }

  const signupIncomplete = mode === "signup" && (
    username.trim().length < 3
    || password.length < 8
    || password !== passwordConfirmation
  );

  return (
    <main className="login-shell">
      <form className="login-panel" onSubmit={(event) => void submit(event)}>
        <div className="brand login-brand">
          <span className="brand-mark" aria-label="0B1T0">0B1T0</span>
          <div><strong>OBITO</strong><span>Chatbot security benchmark</span></div>
        </div>
        <div className="auth-mode-switch" aria-label="Authentication mode">
          <button
            className={mode === "login" ? "active" : ""}
            type="button"
            onClick={() => switchMode("login")}
          >
            Sign in
          </button>
          <button
            className={mode === "signup" ? "active" : ""}
            type="button"
            onClick={() => switchMode("signup")}
          >
            Create account
          </button>
        </div>
        <div>
          <span className="overline">{mode === "login" ? "Account access" : "New researcher"}</span>
          <h1>{mode === "login" ? "Sign in" : "Create account"}</h1>
          <p>
            {mode === "login"
              ? "Access your attack lab sessions, static matrix, and private experiment history."
              : "Your runs and Attack Lab conversations will be saved only to your account."}
          </p>
        </div>
        <label>
          Username
          <input
            value={username}
            minLength={mode === "signup" ? 3 : 1}
            maxLength={mode === "signup" ? 32 : 64}
            pattern={mode === "signup" ? "[A-Za-z0-9][A-Za-z0-9_.-]{2,31}" : undefined}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
            required
          />
          {mode === "signup" && <small>3–32 letters, numbers, dots, underscores, or hyphens</small>}
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            minLength={mode === "signup" ? 8 : 1}
            maxLength={128}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete={mode === "signup" ? "new-password" : "current-password"}
            required
          />
          {mode === "signup" && <small>Use at least 8 characters</small>}
        </label>
        {mode === "signup" && (
          <label>
            Confirm password
            <input
              type="password"
              value={passwordConfirmation}
              minLength={8}
              maxLength={128}
              onChange={(event) => setPasswordConfirmation(event.target.value)}
              autoComplete="new-password"
              required
            />
          </label>
        )}
        {loginError && <small className="login-error">{loginError}</small>}
        <button
          className="auth-submit"
          type="submit"
          disabled={submitting || !username.trim() || !password || signupIncomplete}
        >
          {submitting
            ? mode === "signup" ? "Creating account..." : "Signing in..."
            : mode === "signup" ? "Create account" : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function RunArchive({
  runs,
  error,
  catalog,
}: {
  runs: ArchivedRunSummary[];
  error: string;
  catalog: Catalog;
}) {
  const [visibleRuns, setVisibleRuns] = useState(runs);
  const [selected, setSelected] = useState<ArchivedRunDetail | null>(null);
  const [loadingId, setLoadingId] = useState("");
  const [detailError, setDetailError] = useState("");
  const [exporting, setExporting] = useState("");

  useEffect(() => setVisibleRuns(runs), [runs]);

  const runNumbers = useMemo(() => {
    const chronological = [...visibleRuns].sort(
      (left, right) => new Date(left.started_at).getTime() - new Date(right.started_at).getTime(),
    );
    const counters = { static: 0, adaptive: 0 };
    return new Map(chronological.map((run) => {
      counters[run.kind] += 1;
      return [run.run_id, counters[run.kind]];
    }));
  }, [visibleRuns]);
  const orderedRuns = useMemo(
    () => [...visibleRuns].sort((left, right) => {
      if (left.kind !== right.kind) return left.kind === "static" ? -1 : 1;
      return new Date(right.started_at).getTime() - new Date(left.started_at).getTime();
    }),
    [visibleRuns],
  );

  function runLabel(run: ArchivedRunSummary): string {
    return `${run.kind === "static" ? "Matrix" : "Adaptive"} ${runNumbers.get(run.run_id) ?? 1}`;
  }

  async function inspect(runId: string) {
    setLoadingId(runId);
    setDetailError("");
    try {
      setSelected(await fetchArchivedRun(runId));
    } catch (loadError) {
      setDetailError(loadError instanceof Error ? loadError.message : "Could not load run");
    } finally {
      setLoadingId("");
    }
  }

  async function remove(runId: string) {
    if (!window.confirm("Delete this archived run and its transcript permanently?")) return;
    setDetailError("");
    try {
      await deleteArchivedRun(runId);
      setVisibleRuns((current) => current.filter((run) => run.run_id !== runId));
      if (selected?.run_id === runId) setSelected(null);
    } catch (deleteError) {
      setDetailError(deleteError instanceof Error ? deleteError.message : "Could not delete run");
    }
  }

  async function download(runId: string, format: "csv" | "json") {
    setExporting(`${runId}:${format}`);
    setDetailError("");
    try {
      const blob = await exportArchivedRun(runId, format);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${runId}.${format}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (exportError) {
      setDetailError(exportError instanceof Error ? exportError.message : "Could not export run");
    } finally {
      setExporting("");
    }
  }

  return (
    <section className="run-archive matrix-history">
      <header className="archive-head">
        <div><span className="overline">Saved to this account</span><h2>Run history</h2><p>Open a run, choose an attack × defense cell, and review its complete conversation history.</p></div>
        <strong>{visibleRuns.length} run{visibleRuns.length === 1 ? "" : "s"}</strong>
      </header>
      {(error || detailError) && <div className="archive-error">{error || detailError}</div>}
      {visibleRuns.length === 0 ? (
        <div className="empty-history"><strong>No saved runs yet</strong><p>Complete a static matrix or adaptive run and it will appear here.</p></div>
      ) : (
        <div className="matrix-run-cards">
          {orderedRuns.map((run) => {
            const target = catalog.targets.find((item) => item.id === run.target_id);
            const isSelected = selected?.run_id === run.run_id;
            return (
              <button className={`matrix-run-card ${run.kind} ${isSelected ? "selected" : ""}`} key={run.run_id} onClick={() => void inspect(run.run_id)}>
                <span className="matrix-run-icon" aria-hidden="true">{run.kind === "static" ? "▦" : "↗"}</span>
                <span className="matrix-run-card-copy">
                  <strong>{runLabel(run)}</strong>
                  <small>{target?.name ?? run.target_id} · {new Date(run.completed_at).toLocaleString()}</small>
                  <code>{run.run_id.slice(0, 8)}</code>
                </span>
                <span className="matrix-run-card-score"><strong>{run.success_count}/{run.total_units}</strong><small>successful</small></span>
                <span className={`archive-status ${run.status}`}>{loadingId === run.run_id ? "loading" : run.status.replaceAll("_", " ")}</span>
              </button>
            );
          })}
        </div>
      )}

      {selected && (
        <div className="archive-detail matrix-run-detail">
          <header>
            <div><span className={`archive-kind ${selected.kind}`}>{selected.kind}</span><div><h3>{runLabel(selected)}</h3><small>{new Date(selected.completed_at).toLocaleString()} · {selected.run_id}</small></div></div>
            <div className="archive-actions">
              <button disabled={exporting === `${selected.run_id}:csv`} onClick={() => void download(selected.run_id, "csv")}>CSV</button>
              <button disabled={exporting === `${selected.run_id}:json`} onClick={() => void download(selected.run_id, "json")}>JSON</button>
              <button className="delete-label" onClick={() => void remove(selected.run_id)}>Delete</button>
            </div>
          </header>
          <ArchivedRunEvidence key={selected.run_id} run={selected} catalog={catalog} />
        </div>
      )}
    </section>
  );
}

function ArchivedRunEvidence({ run, catalog }: { run: ArchivedRunDetail; catalog: Catalog }) {
  const staticResult = archivedMatrixRun(run);
  if (staticResult) return <StaticArchiveEvidence result={staticResult} catalog={catalog} />;
  if (run.kind === "static") return <div className="archive-error">This archived static result has an invalid shape.</div>;
  return <AdaptiveArchiveEvidence result={run.result as unknown as AdaptiveRun} catalog={catalog} />;
}

function catalogModelName(catalog: Catalog, modelReference: string): string {
  const separator = modelReference.indexOf(":");
  if (separator < 0) return modelReference;
  const providerId = modelReference.slice(0, separator);
  const modelId = modelReference.slice(separator + 1);
  const provider = catalog.providers.find((item) => item.id === providerId);
  const model = provider?.models.find((item) => item.id === modelId);
  return `${provider?.name ?? providerId} · ${model?.label ?? modelId}`;
}

function StaticArchiveEvidence({ result, catalog }: { result: MatrixRun; catalog: Catalog }) {
  const [selectedCell, setSelectedCell] = useState<{ attackId: string; defenseId: string } | null>(null);

  const attacks = useMemo(
    () => [...new Set(result.cells.map((cell) => cell.attack_id))],
    [result],
  );
  const defenses = useMemo(
    () => [...new Set(result.cells.map((cell) => cell.defense_column_id))]
      .sort((left, right) => left === "baseline" ? -1 : right === "baseline" ? 1 : 0),
    [result],
  );
  const selectedTrials = selectedCell
    ? result.trials.filter((trial) => (
      trial.attack_id === selectedCell.attackId
      && trial.defense_column_id === selectedCell.defenseId
    ))
    : [];
  const selectedAttackName = selectedCell
    ? catalog.attacks.find((item) => item.id === selectedCell.attackId)?.name ?? selectedCell.attackId
    : "";
  const selectedDefenseName = selectedCell
    ? catalog.defense_columns.find((item) => item.id === selectedCell.defenseId)?.name ?? selectedCell.defenseId
    : "";

  return (
    <div className="archive-evidence static-matrix-history">
      <div className="matrix-history-guide">
        <div><span className="overline">Step 1</span><strong>Select a matrix cell</strong><small>Attack rows × defense columns</small></div>
        <span>Click any populated cell to open every matching conversation.</span>
      </div>

      <div className="archive-matrix-table clickable-matrix">
        <table>
          <thead><tr><th>Attack class</th>{defenses.map((defenseId) => <th key={defenseId}>{catalog.defense_columns.find((item) => item.id === defenseId)?.name ?? defenseId}</th>)}</tr></thead>
          <tbody>{attacks.map((attackId) => (
            <tr key={attackId}>
              <td><strong>{catalog.attacks.find((item) => item.id === attackId)?.name ?? attackId}</strong></td>
              {defenses.map((defenseId) => {
                const trials = result.trials.filter((trial) => trial.attack_id === attackId && trial.defense_column_id === defenseId);
                const successes = trials.filter((trial) => trial.success).length;
                const blocked = trials.filter((trial) => !trial.model_called).length;
                const isSelected = selectedCell?.attackId === attackId && selectedCell.defenseId === defenseId;
                return (
                  <td className={`${successes ? "has-success" : "no-success"} ${isSelected ? "selected" : ""}`} key={defenseId}>
                    {trials.length ? (
                      <button onClick={() => setSelectedCell({ attackId, defenseId })}>
                        <strong>{(100 * successes / trials.length).toFixed(0)}%</strong>
                        <small>{successes}/{trials.length} attack success · {blocked} blocked</small>
                        <span>Open {trials.length} conversation{trials.length === 1 ? "" : "s"} →</span>
                      </button>
                    ) : <span className="empty-matrix-cell">N/A</span>}
                  </td>
                );
              })}
            </tr>
          ))}</tbody>
        </table>
      </div>

      {selectedCell ? (
        <section className="matrix-cell-history">
          <header>
            <div><span className="overline">Step 2 · Conversation history</span><h3>{selectedAttackName} × {selectedDefenseName}</h3><p>Every trial stored for this matrix intersection.</p></div>
            <div className="cell-history-count"><strong>{selectedTrials.filter((trial) => trial.success).length}/{selectedTrials.length}</strong><span>attacks succeeded</span></div>
          </header>
          <div className="cell-conversations">
            {selectedTrials.map((trial, index) => {
              const outcome = !trial.model_called ? "blocked" : trial.success ? "success" : "failed";
              return (
                <article className={`archive-conversation static-conversation ${outcome}`} key={`${trial.attack_instance_id}:${trial.model_id}:${trial.trial_index}:${index}`}>
                  <header>
                    <div><strong>Trial {trial.trial_index + 1} · {trial.attack_definition_name}</strong><small>{catalogModelName(catalog, trial.model_id)}</small></div>
                    <span className={`attempt-verdict ${outcome}`}>{outcome === "success" ? "Attack succeeded" : outcome === "blocked" ? "Blocked" : "Attack failed"}</span>
                  </header>
                  <article className="lab-message user"><label>Attacker</label><div>{trial.attack_input}</div></article>
                  {trial.attack_context && <article className="lab-message attacker-model"><label>Injected {trial.attack_delivery.replaceAll("_", " ")}</label><div>{trial.attack_context}</div></article>}
                  <article className="lab-message assistant"><label>Target through {selectedDefenseName}</label><div>{trial.visible_output || (trial.model_called ? "No visible output" : "Request blocked before the model was called")}</div></article>
                  <footer className="archive-episode-footer">
                    <span>{trial.input_tokens + trial.output_tokens} tokens</span>
                    <span>{trial.model_latency_ms.toFixed(0)} ms model latency</span>
                    <span>{trial.defense_latency_ms.toFixed(1)} ms defense latency</span>
                    {trial.raw_model_disclosure && <span>Raw disclosure detected</span>}
                  </footer>
                </article>
              );
            })}
          </div>
        </section>
      ) : (
        <div className="matrix-cell-placeholder"><span>↑</span><strong>Select one matrix cell</strong><p>Its saved attack and target messages will appear here as a conversation.</p></div>
      )}
    </div>
  );
}

function AdaptiveArchiveEvidence({ result, catalog }: { result: AdaptiveRun; catalog: Catalog }) {
  return (
    <div className="archive-evidence">
      <div className="archive-summary-grid">
        <article><span>Attack success rate</span><strong>{result.asr_percent.toFixed(1)}%</strong><small>{result.success_count}/{result.total_episodes} episodes</small></article>
        <article><span>Target queries</span><strong>{result.total_target_queries}</strong><small>across all episodes</small></article>
        <article><span>Model calls</span><strong>{result.budget.target_calls}</strong><small>{result.budget.attacker_calls} attacker calls</small></article>
        <article><span>Status</span><strong>{result.status.replaceAll("_", " ")}</strong><small>{result.budget.elapsed_seconds.toFixed(1)} seconds</small></article>
      </div>
      <div className="archive-chat">
      {result.episodes.map((episode, episodeIndex) => (
        <section className="archive-conversation" key={`${episode.attack_instance_id}:${episode.defense_column_id}:${episodeIndex}`}>
          <header>
            <div><strong>{catalog.defense_columns.find((column) => column.id === episode.defense_column_id)?.name ?? episode.defense_column_id}</strong><small>{episode.model_id} · seed {episode.attack_seed}</small></div>
            <span className={`attempt-verdict ${episode.success ? "success" : "failed"}`}>{episode.success ? "Success" : "Failed"}</span>
          </header>
          {episode.trace.map((event) => event.kind === "message" ? (
            <div className="archive-turn" key={event.event_index}>
              <article className="lab-message user"><label>Attacker · {event.phase}</label><div>{event.attack_input || "No attack input recorded"}</div></article>
              <article className="lab-message assistant"><label>Target</label><div>{event.visible_output || "No attacker-visible output"}</div><footer><span>{event.status.replaceAll("_", " ")}</span>{event.raw_model_disclosure && <span className="blocked-badge">Raw disclosure detected</span>}</footer></article>
            </div>
          ) : event.kind === "attacker_proposal" ? (
            <article className="lab-message attacker-model" key={event.event_index}><label>Attacker model proposal</label><div>{event.attacker_output || event.attacker_instruction || "Proposal recorded"}</div></article>
          ) : (
            <article className="archive-oracle-event" key={event.event_index}><strong>{event.kind === "submission" ? "Oracle submission" : "Episode stopped"}</strong><span>{event.status.replaceAll("_", " ")}</span>{event.candidate && <code>{event.candidate}</code>}</article>
          ))}
          <footer className="archive-episode-footer"><span>{episode.target_queries} target calls</span><span>{episode.attacker_queries} attacker calls</span><span>{episode.terminal_reason.replaceAll("_", " ")}</span></footer>
        </section>
      ))}
      </div>
    </div>
  );
}

type LabTranscriptItem =
  | { role: "user"; content: string }
  | { role: "assistant"; content: string; result: LabMessageResult };

function AttackLab({
  catalog,
  selectedTarget,
  selectedProvider,
  selectedModel,
  credentials,
  modelSelections,
  temperature,
  availableProviders,
  onProviderChange,
}: {
  catalog: Catalog;
  selectedTarget: TargetId;
  selectedProvider: ProviderId;
  selectedModel: string;
  credentials: Record<ProviderId, string>;
  modelSelections: Record<ProviderId, string>;
  temperature: number;
  availableProviders: ProviderId[];
  onProviderChange: (providerId: ProviderId) => void;
}) {
  const target = catalog.targets.find((item) => item.id === selectedTarget)!;
  const [prompt, setPrompt] = useState("");
  const [defenseColumn, setDefenseColumn] = useState("combo:d6_legacy");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [activeSession, setActiveSession] = useState<LabSessionDetail | null>(null);
  const [labSessions, setLabSessions] = useState<LabSession[]>([]);
  const [transcript, setTranscript] = useState<LabTranscriptItem[]>([]);
  const [sending, setSending] = useState(false);
  const [labError, setLabError] = useState("");
  const [candidate, setCandidate] = useState("");
  const [submissionStatus, setSubmissionStatus] = useState<"" | "success" | "incorrect">("");
  const [confirmedSuccessTurn, setConfirmedSuccessTurn] = useState<number | null>(null);
  const [adaptiveRun, setAdaptiveRun] = useState<AdaptiveRun | null>(null);
  const [runningAdaptive, setRunningAdaptive] = useState(false);
  const [adaptivePolicy, setAdaptivePolicy] = useState<"crescendo" | "pair" | "tap">("crescendo");
  const [attackerProvider, setAttackerProvider] = useState<ProviderId>(selectedProvider);
  const [adaptiveTrials, setAdaptiveTrials] = useState(1);
  const [adaptiveMaxQueries, setAdaptiveMaxQueries] = useState(8);

  const activeProviderId = activeSession?.provider_id ?? selectedProvider;
  const activeProvider = catalog.providers.find((item) => item.id === activeProviderId)!;
  const activeApiKey = credentials[activeProviderId];
  const providerExecutable = activeProviderId === "groq" || activeProviderId === "openai" || activeProviderId === "anthropic";
  const sessionEnded = activeSession?.status === "failed";
  const liveReady = !sessionEnded && providerExecutable && (Boolean(activeApiKey) || activeProvider.configured_from_env);
  const attackerCatalogProvider = catalog.providers.find((item) => item.id === attackerProvider)!;
  const attackerReady = Boolean(credentials[attackerProvider]) || attackerCatalogProvider.configured_from_env;
  const selectedAdaptivePolicy = catalog.adaptive_policies.find((policy) => policy.id === adaptivePolicy);
  const usesAttackerModel = selectedAdaptivePolicy?.requires_attacker_model ?? false;
  const adaptiveArmCount = adaptiveTrials * (defenseColumn === "baseline" ? 1 : 2);
  const adaptiveCallCeiling = adaptiveArmCount * adaptiveMaxQueries;
  const adaptiveBudgetValid = adaptiveCallCeiling <= 120;
  const defenseOptions = catalog.defense_columns.filter(
    (column) => column.applicable_target_ids.includes(selectedTarget)
      && column.defense_variant_ids.every(
        (id) => catalog.defense_variants.find((variant) => variant.id === id)?.implementation_status === "executable",
      ),
  );
  const adaptivePolicies = catalog.adaptive_policies.filter(
    (policy) => policy.applicable_target_ids.includes(selectedTarget),
  );
  const successfulSessions = labSessions.filter((session) => session.status === "success").length;
  const failedSessions = labSessions.filter((session) => session.status === "failed").length;

  async function refreshLabSessions() {
    try {
      setLabSessions(await fetchLabSessions());
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Could not load Attack Lab history");
    }
  }

  useEffect(() => {
    void refreshLabSessions();
  }, []);

  useEffect(() => {
    setSessionId(null);
    setActiveSession(null);
    setTranscript([]);
    setPrompt("");
    setCandidate("");
    setSubmissionStatus("");
    setConfirmedSuccessTurn(null);
    setAdaptiveRun(null);
    setLabError("");
    setAttackerProvider(selectedProvider);
    setDefenseColumn(selectedTarget === "chatbot" ? "combo:d6_legacy" : "baseline");
    const firstPolicy = catalog.adaptive_policies.find(
      (policy) => policy.applicable_target_ids.includes(selectedTarget),
    );
    if (firstPolicy) {
      setAdaptivePolicy(firstPolicy.id);
    }
  }, [selectedTarget, selectedProvider, selectedModel, temperature]);

  function resetSession() {
    setSessionId(null);
    setActiveSession(null);
    setTranscript([]);
    setPrompt("");
    setCandidate("");
    setSubmissionStatus("");
    setConfirmedSuccessTurn(null);
    setLabError("");
  }

  async function loadSession(id: string) {
    setLabError("");
    try {
      const detail = await fetchLabSession(id);
      setActiveSession(detail);
      setSessionId(detail.session_id);
      setTranscript(detail.turns.flatMap((turn) => [
        { role: "user" as const, content: turn.user_input },
        { role: "assistant" as const, content: turn.result.visible_output, result: turn.result },
      ]));
      setSubmissionStatus("");
      setConfirmedSuccessTurn(detail.status === "success" && detail.turn_count > 0 ? detail.turn_count : null);
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Could not load Attack Lab session");
    }
  }

  async function endSession() {
    if (sessionId) {
      try {
        await closeLabSession(sessionId);
        await refreshLabSessions();
      } catch (error) {
        setLabError(error instanceof Error ? error.message : "Could not end session");
        return;
      }
    }
    resetSession();
  }

  async function removeSession(id: string) {
    if (!window.confirm("Delete this Attack Lab conversation permanently?")) return;
    try {
      await deleteLabSession(id);
      setLabSessions((current) => current.filter((session) => session.session_id !== id));
      if (sessionId === id) resetSession();
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Could not delete session");
    }
  }

  async function handleSend() {
    const content = prompt.trim();
    if (!content || !liveReady || sending) return;
    setSending(true);
    setLabError("");
    try {
      let activeSessionId = sessionId;
      if (!activeSessionId) {
        const session = await createLabSession({
          target_id: selectedTarget,
          provider_id: selectedProvider,
          model_id: selectedModel,
          temperature,
          defense_column_id: defenseColumn,
        });
        activeSessionId = session.session_id;
        setSessionId(activeSessionId);
      }
      const messageProviderId = activeSession?.provider_id ?? selectedProvider;
      const result = await sendLabMessage(activeSessionId, credentials[messageProviderId] || null, content);
      setTranscript((current) => [
        ...current,
        { role: "user", content },
        { role: "assistant", content: result.visible_output, result },
      ]);
      setPrompt("");
      await refreshLabSessions();
      await loadSession(activeSessionId);
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Attack Lab request failed");
    } finally {
      setSending(false);
    }
  }

  async function handleSubmit() {
    if (!sessionId || !candidate.trim()) return;
    setLabError("");
    try {
      const result = await submitLabCandidate(sessionId, candidate.trim());
      setSubmissionStatus(result.success ? "success" : "incorrect");
      if (result.success) {
        const latestTurn = Math.floor(transcript.length / 2);
        setConfirmedSuccessTurn(latestTurn);
      }
      await refreshLabSessions();
      await loadSession(sessionId);
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Candidate submission failed");
    }
  }

  async function handleAdaptiveRun() {
    if (!liveReady || (usesAttackerModel && !attackerReady) || !adaptiveBudgetValid || runningAdaptive || !adaptivePolicies.length) return;
    setRunningAdaptive(true);
    setLabError("");
    try {
      const result = await runAdaptiveMatrix({
        target_id: selectedTarget,
        attack_id: adaptivePolicy,
        model_ids: [`${selectedProvider}:${selectedModel}`],
        attacker_model_id: usesAttackerModel
          ? `${attackerProvider}:${modelSelections[attackerProvider]}`
          : null,
        defense_column_ids: [defenseColumn],
        trials: adaptiveTrials,
        temperature,
        max_queries: adaptiveMaxQueries,
        max_attacker_queries: adaptiveMaxQueries,
        max_submissions: 16,
        max_branches: 4,
        credentials: Object.fromEntries(
          [...new Set([selectedProvider, ...(usesAttackerModel ? [attackerProvider] : [])])]
            .filter((providerId) => Boolean(credentials[providerId]))
            .map((providerId) => [providerId, credentials[providerId]]),
        ),
      });
      setAdaptiveRun(result);
    } catch (error) {
      setLabError(error instanceof Error ? error.message : "Adaptive run failed");
    } finally {
      setRunningAdaptive(false);
    }
  }

  return (
    <section className="attack-lab">
      <header className="lab-header">
        <div><h2>Manual Attack Lab</h2><p>Inspect one target and one defense condition turn by turn before adding the attack to the matrix.</p></div>
        <div className="lab-state"><span className={`status-light ${liveReady ? "" : "warning"}`} />{sessionEnded ? "Saved session ended" : liveReady ? `${activeProvider.name} runner ready` : `Enter an ${activeProvider.name} key`}</div>
      </header>
      <div className="lab-toolbar">
        <label>Application<strong>{target.name}</strong></label>
        <label>Backend<select value={selectedProvider} onChange={(event) => onProviderChange(event.target.value as ProviderId)}>{availableProviders.map((providerId) => {
          const option = catalog.providers.find((item) => item.id === providerId)!;
          return <option key={option.id} value={option.id}>{option.name}</option>;
        })}</select></label>
        <label>Model<strong>{selectedModel}</strong></label>
        <label>Defense condition<select value={defenseColumn} onChange={(event) => { setDefenseColumn(event.target.value); resetSession(); }}>{defenseOptions.map((column) => <option key={column.id} value={column.id}>{column.name}</option>)}</select></label>
        <label>Adaptive policy<select value={adaptivePolicy} onChange={(event) => { setAdaptivePolicy(event.target.value as typeof adaptivePolicy); setAdaptiveRun(null); }}>{adaptivePolicies.map((attack) => <option key={attack.id} value={attack.id}>{attack.name}</option>)}</select></label>
        <label>Independent seeds<input type="number" min={1} max={10} value={adaptiveTrials} onChange={(event) => { setAdaptiveTrials(Math.max(1, Math.min(10, Number(event.target.value) || 1))); setAdaptiveRun(null); }} /></label>
        <label>Queries / arm<input type="number" min={1} max={20} value={adaptiveMaxQueries} onChange={(event) => { setAdaptiveMaxQueries(Math.max(1, Math.min(20, Number(event.target.value) || 1))); setAdaptiveRun(null); }} /></label>
        {usesAttackerModel && <label>Attacker backend<select value={attackerProvider} onChange={(event) => { setAttackerProvider(event.target.value as ProviderId); setAdaptiveRun(null); }}>{availableProviders.map((providerId) => <option key={providerId} value={providerId}>{catalog.providers.find((item) => item.id === providerId)?.name}</option>)}</select></label>}
        {usesAttackerModel && <label>Attacker model<strong>{modelSelections[attackerProvider]}</strong></label>}
        <button onClick={() => void endSession()}>{sessionId ? "End session" : "New session"}</button>
        <button className="adaptive-run-button" disabled={!liveReady || (usesAttackerModel && !attackerReady) || !adaptiveBudgetValid || runningAdaptive || !adaptivePolicies.length} onClick={() => void handleAdaptiveRun()} title={`${adaptiveCallCeiling} maximum target calls`}>{runningAdaptive ? "Running adaptive…" : !adaptiveBudgetValid ? "Reduce seeds or queries" : `Run paired ${adaptivePolicy.toUpperCase()} · ≤${adaptiveCallCeiling} calls`}</button>
      </div>
      <div className="lab-workbench">
        <div className="lab-chat">
          <div className="chat-history-head">
            <div><strong>Conversation</strong><span>{sessionId ? `${catalog.targets.find((item) => item.id === activeSession?.target_id)?.name ?? target.name} · ${activeSession?.model_id ?? selectedModel}` : "No active session"}</span></div>
            <span>{Math.floor(transcript.length / 2)} attack turn{transcript.length === 2 ? "" : "s"}</span>
          </div>
          <div className="lab-canvas">
            {transcript.length === 0 ? (
              <div className="empty-transcript">
                <span>01</span>
                <h3>Start a controlled session</h3>
                <p>The Chatbot uses the original fixed synthetic flag. Only attacker-visible output appears here.</p>
                <small>Oracle: {target.oracle}</small>
              </div>
            ) : (
              <div className="lab-transcript">
                {transcript.map((item, index) => item.role === "user" ? (
                  <article className="lab-message user" key={index}><label>Attacker</label><div>{item.content}</div></article>
                ) : (
                  <article className="lab-message assistant" key={index}>
                    <label>Target · Turn {item.result.turn}</label>
                    <div>{item.content}</div>
                    <footer>
                      <span className={`attempt-verdict ${item.result.visible_exact_leak || confirmedSuccessTurn === item.result.turn ? "success" : "in-progress"}`}>{item.result.visible_exact_leak || confirmedSuccessTurn === item.result.turn ? "Success" : "No proof yet"}</span>
                      {item.result.visible_exact_leak && <span className="leak-badge">Exact visible leak</span>}
                      <span>{item.result.input_tokens + item.result.output_tokens} tokens</span>
                      <span>{item.result.estimated_cost_usd === null ? "cost unavailable" : `$${item.result.estimated_cost_usd.toFixed(5)}`}</span>
                      <span>{item.result.model_latency_ms.toFixed(0)} ms model</span>
                    </footer>
                    <details className="research-trace"><summary>Researcher trace</summary><div>{item.result.raw_model_disclosure && !item.result.visible_exact_leak && <span className="blocked-badge">Raw disclosure filtered</span>}{item.result.verdicts.map((verdict) => <span key={verdict.defense_id}>{verdict.defense_id}: {verdict.action}</span>)}</div></details>
                  </article>
                ))}
              </div>
            )}
          </div>
          <div className="lab-composer">
            <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) void handleSend(); }} placeholder="Enter an authorized test prompt…" />
            <div><span>{labError || "Ctrl/⌘ + Enter to send. API keys are never stored in sessions."}</span><button disabled={!liveReady || !prompt.trim() || sending} onClick={() => void handleSend()}>{sending ? "Running…" : "Send attack turn"}</button></div>
          </div>
          {sessionId && !sessionEnded && <div className="submission-bar"><div><strong>Exact recovery submission</strong><span>Submit the reconstructed protected value; similarity alone cannot succeed.</span></div><input type="password" value={candidate} onChange={(event) => { setCandidate(event.target.value); setSubmissionStatus(""); }} placeholder="Recovered candidate" /><button disabled={!candidate.trim()} onClick={() => void handleSubmit()}>Submit</button>{submissionStatus && <em className={submissionStatus}>{submissionStatus === "success" ? "Exact leak confirmed" : "Incorrect candidate"}</em>}</div>}
        </div>
        <aside className="attack-history">
          <header>
            <div><strong>Chat history</strong><span>Stored in the local research database</span></div>
            <div className="history-counts"><span className="success">{successfulSessions} success</span><span>{labSessions.length - successfulSessions - failedSessions} active</span><span className="failed">{failedSessions} failed</span></div>
          </header>
          {labSessions.length === 0 ? (
            <div className="empty-history"><span>⌁</span><strong>No saved conversations</strong><p>Your first attack session will remain here after reloads and server restarts.</p></div>
          ) : (
            <div className="attack-history-list">
              {labSessions.map((savedSession) => (
                <article className={`attack-history-item ${savedSession.status} ${sessionId === savedSession.session_id ? "selected" : ""}`} key={savedSession.session_id}>
                  <button className="saved-session-open" onClick={() => void loadSession(savedSession.session_id)}>
                    <div className="history-item-head">
                      <span>{catalog.targets.find((item) => item.id === savedSession.target_id)?.name ?? savedSession.target_id} · {savedSession.session_id.slice(0, 6)}</span>
                      <strong>{savedSession.status === "success" ? "Success" : savedSession.status === "failed" ? "Failed" : "Active"}</strong>
                    </div>
                    <p className="history-prompt">{savedSession.model_id}</p>
                    <p className="history-output">{catalog.defense_columns.find((column) => column.id === savedSession.defense_column_id)?.name ?? savedSession.defense_column_id}</p>
                    <footer>
                      <span>{savedSession.turn_count} turn{savedSession.turn_count === 1 ? "" : "s"}</span>
                      <time dateTime={savedSession.updated_at}>{new Date(savedSession.updated_at).toLocaleString()}</time>
                    </footer>
                  </button>
                  <button className="delete-label" onClick={() => void removeSession(savedSession.session_id)}>Delete</button>
                </article>
              ))}
            </div>
          )}
        </aside>
      </div>
      {adaptiveRun && (
        <section className="adaptive-results">
          <header><div><span className="overline">Visible-only policy · {adaptiveRun.status.replace("_", " ")}</span><h3>Paired adaptive {adaptiveRun.attack_id.toUpperCase()} result</h3></div><strong>{adaptiveRun.success_count}/{adaptiveRun.total_episodes} successful</strong></header>
          <div className="adaptive-run-summary">
            <div><span>Target calls</span><strong>{adaptiveRun.budget.target_calls}</strong></div>
            <div><span>Attacker calls</span><strong>{adaptiveRun.budget.attacker_calls}</strong></div>
            <div><span>Total tokens</span><strong>{adaptiveRun.budget.input_tokens + adaptiveRun.budget.output_tokens}</strong></div>
            <div><span>Elapsed</span><strong>{adaptiveRun.budget.elapsed_seconds.toFixed(2)} s</strong></div>
          </div>
          <div className="adaptive-success-curve">
            {adaptiveRun.success_at_k.map((point) => (
              <div key={`${point.model_id}:${point.defense_column_id}:${point.query_budget}`}>
                <span>{catalog.defense_columns.find((column) => column.id === point.defense_column_id)?.name ?? point.defense_column_id} · success@{point.query_budget}</span>
                <strong>{point.success_rate_percent.toFixed(0)}%</strong>
                <small>95% CI {point.ci_low_percent.toFixed(0)}–{point.ci_high_percent.toFixed(0)} · n={point.episode_n}</small>
              </div>
            ))}
          </div>
          <div className="adaptive-episodes">
            {adaptiveRun.episodes.map((episode) => (
              <article className={episode.success ? "success" : "failed"} key={`${episode.defense_column_id}:${episode.trial_index}`}>
                <header><strong>{catalog.defense_columns.find((column) => column.id === episode.defense_column_id)?.name ?? episode.defense_column_id}</strong><span>{episode.success ? "Success" : "Failed"}</span></header>
                <div className="episode-stats"><span>{episode.target_queries} target calls</span><span>{episode.attacker_queries} attacker calls</span><span>{episode.submissions} submissions</span><span>{episode.estimated_cost_usd === null ? "target cost unavailable" : `$${episode.estimated_cost_usd.toFixed(5)} target`}</span><span>{episode.attacker_estimated_cost_usd === null ? "no attacker cost" : `$${episode.attacker_estimated_cost_usd.toFixed(5)} attacker`}</span><span>{episode.terminal_reason.replaceAll("_", " ")}</span></div>
                <div className="adaptive-trace">
                  {episode.trace.map((event) => (
                    <div className={`adaptive-event ${event.status}`} key={event.event_index}>
                      <strong>{event.kind === "message" ? `Turn ${event.event_index} · ${event.phase}` : event.kind}</strong>
                      {event.attacker_instruction && <p>{event.attacker_instruction}</p>}
                      {event.attacker_output && <p>{event.attacker_output}</p>}
                      {event.attack_input && <p>{event.attack_input}</p>}
                      {event.visible_output && <p>{event.visible_output}</p>}
                      <span>{event.status.replaceAll("_", " ")}</span>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
        </section>
      )}
    </section>
  );
}
