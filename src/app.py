import streamlit as st
from utils import parse_email, get_heuristic_score

st.set_page_config(page_title="Phishing Inspector", page_icon="🛡️")

st.title("🛡️ Hybrid AI Phishing Detector")
st.markdown("Upload a raw `.eml` file to scan for threats.")

uploaded_file = st.file_uploader("Upload Email File", type=["eml"])

if uploaded_file is not None:
    # 1. Parse the Email using our utility
    email_data = parse_email(uploaded_file)
    
    if "error" in email_data:
        st.error(f"Failed to parse email: {email_data['error']}")
    else:
        # Display Basic Info
        st.subheader("📧 Email Meta-Data")
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**From:** {email_data['from']}")
        with col2:
            st.info(f"**Subject:** {email_data['subject']}")

        # 2. Run Heuristics (The logic you wrote)
        st.divider()
        st.subheader("🔍 Security Analysis")
        
        with st.spinner("Analyzing Headers & Content..."):
            tech_score, reasons = get_heuristic_score(email_data)
            
            # Display Score
            st.metric(label="Risk Score (Rule-Based Only)", value=f"{tech_score}/100")
            
            if reasons:
                st.warning("⚠️ Red Flags Detected:")
                for reason in reasons:
                    st.write(f"- {reason}")
            else:
                st.success("✅ No technical anomalies detected.")

        # Placeholder for Phase 5 (AI Model)
        st.info("🤖 Deep Learning Analysis: [Model Not Loaded Yet - Coming in Phase 3]")