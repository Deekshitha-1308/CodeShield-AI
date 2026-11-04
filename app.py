import json
import streamlit as st
from analyzer import analyze_code
from ai_review import get_ai_review

st.set_page_config(page_title="CodeShield AI", page_icon="🛡️", layout="wide")
st.title("🛡️ CodeShield AI")
st.caption("AI-powered code review • Bugs • Security • Quality • Actionable fixes")

with st.sidebar:
    st.header("Review settings")
    use_ai = st.toggle("Enable AI explanations", value=True)
    st.info("Static checks work without an API key. AI explanations require OPENAI_API_KEY.")
    st.markdown("**Supported:** Python source code")
    st.markdown("**Demo tip:** Try the vulnerable sample in the `samples` folder.")

sample_path = "samples/vulnerable_sample.py"
try:
    sample_code = open(sample_path, encoding="utf-8").read()
except OSError:
    sample_code = "def divide(a, b):\n    return a / b\n"

uploaded = st.file_uploader("Upload a Python file", type=["py"])
default_code = uploaded.getvalue().decode("utf-8", errors="replace") if uploaded else sample_code
code = st.text_area("Or paste your code here", value=default_code, height=330)

if st.button("🔍 Review my code", type="primary", use_container_width=True):
    if not code.strip():
        st.warning("Please paste or upload some Python code first.")
    else:
        with st.spinner("Scanning code..."):
            findings = analyze_code(code)
            ai_text = ""
            if use_ai:
                ai_text = get_ai_review(code, findings)

        counts = {level: sum(1 for f in findings if f["severity"] == level)
                  for level in ["Critical", "High", "Medium", "Low", "Info"]}
        cols = st.columns(5)
        for col, level in zip(cols, counts):
            col.metric(level, counts[level])

        st.subheader("Review findings")
        if not findings:
            st.success("No issues detected by the built-in checks. This does not guarantee the code is bug-free.")
        for item in findings:
            title = f'{item["severity"]} · {item["category"]} · Line {item["line"]}'
            with st.expander(title, expanded=item["severity"] in ("Critical", "High")):
                st.write(item["message"])
                st.code(item["evidence"], language="python")
                st.markdown(f'**Suggested fix:** {item["suggestion"]}')

        if use_ai:
            st.subheader("🤖 AI review")
            if ai_text:
                st.markdown(ai_text)
            else:
                st.info("AI review was skipped. Add OPENAI_API_KEY to your environment to enable it.")

        report = {"tool": "CodeShield AI", "findings": findings, "ai_review": ai_text}
        st.download_button("⬇️ Download review report (JSON)",
                           data=json.dumps(report, indent=2),
                           file_name="codeshield_review.json",
                           mime="application/json")
        st.caption("Important: Treat findings as suggestions. Validate fixes with tests and a human reviewer.")
