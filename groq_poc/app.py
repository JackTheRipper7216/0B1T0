"""Streamlit frontend for the pack-hunt proof-of-concept.

Three tabs:
  - Chat        : talk to SupportBot, optionally with defenses on, and try to
                  extract the flag.
  - Attack Lab  : fire the graded attack suite (no defenses) and see which leaks.
  - Showdown    : run attacks x defense levels and render the who-wins matrix.

Run:  streamlit run app.py
"""
import streamlit as st

from chatbot import SupportBot, SYSTEM_PROMPT, FLAG, MODEL
from attack import ATTEMPTS, FLAG_PREFIX
from defenses import (
    HARDENED_SYSTEM_PROMPT, input_filter, output_filter_exact,
    output_filter_fuzzy, DEFENSE_LEVELS, build_bot, leaked,
)

st.set_page_config(page_title="Pack-Hunt PoC", page_icon="🎯", layout="wide")


# --- Sidebar: credentials, model, and the defense stack ----------------------
with st.sidebar:
    st.header("⚙️ Config")
    api_key = st.text_input(
        "Groq API key", type="password",
        help="Free key at console.groq.com → API Keys. Kept in this session "
             "only, never written to disk.",
    )
    model = st.text_input("Model", value=MODEL)
    temperature = st.slider("Temperature", 0.0, 1.0, 0.4, 0.1,
                            help="Higher = more random. Borderline attacks leak "
                                 "more often at higher temperature.")

    st.divider()
    st.subheader("🛡️ Defenses (for Chat)")
    d_harden = st.checkbox("Prompt hardening", help="Stricter system prompt.")
    d_input = st.checkbox("Input filter", help="Block obvious injection.")
    d_output = st.radio("Output filter", ["none", "exact", "fuzzy"],
                        help="exact = redact identical flag (typo beats it); "
                             "fuzzy = recoverability-aware.")
    st.caption("Access control & human-in-the-loop apply to the RAG/agent "
               "targets, not this chatbot.")

    st.divider()
    with st.expander("Show planted flag / system prompt"):
        st.code(SYSTEM_PROMPT, language="text")


def require_key():
    if not api_key:
        st.info("Enter your Groq API key in the sidebar to begin.")
        st.stop()


def chat_bot():
    """Bot built from the sidebar defense toggles."""
    out = {"none": None, "exact": output_filter_exact,
           "fuzzy": output_filter_fuzzy}[d_output]
    return SupportBot(
        api_key=api_key, model=model, temperature=temperature,
        system_prompt=HARDENED_SYSTEM_PROMPT if d_harden else None,
        input_filter=input_filter if d_input else None,
        output_filter=out,
    )


st.title("🎯 Pack-Hunt Proof-of-Concept")
st.caption("Intentionally vulnerable chatbot + graded attacks + escalating "
           "defenses. Authorized defensive research — the flag is fake.")

tab_chat, tab_attack, tab_show = st.tabs(
    ["💬 Chat", "🧪 Attack Lab", "🥊 Showdown"])


# --- Tab 1: interactive chat (defenses honored) ------------------------------
with tab_chat:
    active = [n for n, on in
              [("harden", d_harden), ("input", d_input)] if on]
    if d_output != "none":
        active.append(f"output:{d_output}")
    st.caption("Active defenses: " + (", ".join(active) if active else "none"))

    if "history" not in st.session_state:
        st.session_state.history = []
    if st.button("🗑️ Clear conversation"):
        st.session_state.history = []

    for turn in st.session_state.history:
        with st.chat_message(turn["role"]):
            st.markdown(turn["content"])

    prompt = st.chat_input("Message SupportBot…")
    if prompt:
        require_key()
        bot = chat_bot()
        st.session_state.history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("thinking…"):
                reply = bot.ask(prompt, st.session_state.history[:-1])
            st.markdown(reply)
            if leaked(reply):
                st.error("🚩 FLAG LEAKED — recoverable secret in the output!")
            elif reply.startswith("[BLOCKED") or reply.startswith("[OUTPUT BLOCKED"):
                st.success("🛡️ Defense held — attack stopped.")
        st.session_state.history.append({"role": "assistant", "content": reply})


# --- Tab 2: graded attack suite (no defenses) --------------------------------
with tab_attack:
    st.subheader("Graded attack suite (undefended baseline)")
    st.markdown(f"**Target flag:** `{FLAG}`")
    if st.button("▶️ Run all attacks", type="primary"):
        require_key()
        results = []
        bar = st.progress(0.0, text="Running…")
        for i, (name, desc, payload) in enumerate(ATTEMPTS):
            reply = SupportBot(api_key=api_key, model=model,
                               temperature=temperature).ask(payload)
            results.append((name, desc, payload, reply, leaked(reply)))
            bar.progress((i + 1) / len(ATTEMPTS), text=f"Ran {name}")
        bar.empty()

        n_leak = sum(1 for *_, lk in results if lk)
        st.metric("ASR (undefended)", f"{n_leak}/{len(results)}")
        for name, desc, payload, reply, lk in results:
            icon = "🚩" if lk else "✅"
            with st.expander(f"{icon} {name} — {'LEAKED' if lk else 'held'} · {desc}"):
                st.markdown("**Payload**"); st.code(payload, language="text")
                st.markdown("**Reply**")
                (st.error if lk else st.success)(reply)


# --- Tab 3: the showdown matrix ----------------------------------------------
with tab_show:
    st.subheader("Attack × Defense showdown")
    st.caption("Each cell = leaks out of N runs, scored by the recoverability "
               "oracle. Lower = defense winning.")
    n_runs = st.slider("Runs per cell (N)", 1, 5, 2)
    est = len(ATTEMPTS) * len(DEFENSE_LEVELS) * n_runs
    st.caption(f"⚠️ Runs up to **{est}** API requests "
               f"({len(ATTEMPTS)} attacks × {len(DEFENSE_LEVELS)} defenses × {n_runs}).")

    if st.button("🥊 Run showdown", type="primary"):
        require_key()
        codes = [d[0] for d in DEFENSE_LEVELS]
        grid = {}
        bar = st.progress(0.0, text="Running…")
        cells = len(ATTEMPTS) * len(DEFENSE_LEVELS)
        done = 0
        for name, _desc, payload in ATTEMPTS:
            for label, opts in DEFENSE_LEVELS:
                leaks = 0
                for _ in range(n_runs):
                    reply = build_bot(opts, api_key, model, temperature).ask(payload)
                    if leaked(reply):
                        leaks += 1
                grid[(name, label)] = leaks
                done += 1
                bar.progress(done / cells, text=f"{name} vs {label}")
        bar.empty()

        # render as a markdown table with emoji per cell
        head = "| Attack | " + " | ".join(c.split()[0] for c in codes) + " |"
        sep = "|" + "---|" * (len(codes) + 1)
        lines = [head, sep]
        for name, _d, _p in ATTEMPTS:
            short = name.split(". ", 1)[-1]
            cells_md = []
            for label in codes:
                lk = grid[(name, label)]
                mark = "🚩" if lk else "✅"
                cells_md.append(f"{mark} {lk}/{n_runs}")
            lines.append(f"| {short} | " + " | ".join(cells_md) + " |")
        st.markdown("\n".join(lines))

        survivors = [n.split(". ", 1)[-1] for n, _d, _p in ATTEMPTS
                     if grid[(n, codes[-1])] > 0]
        if survivors:
            st.error("Survives **D6 MAX**: " + ", ".join(survivors))
        else:
            st.success("Every attack stopped at D6 MAX.")
        st.caption("Legend: " + " · ".join(
            f"**{c.split()[0]}** {c.split(' ', 1)[1]}" for c in codes))
