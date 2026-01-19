import streamlit as st
import pandas as pd
import json
import requests
import os
from sqlalchemy import create_engine
from streamlit_google_auth import Authenticate

# --- 0. PRODUCTION CREDENTIALS RECONSTRUCTION ---
if "GOOGLE_CREDENTIALS_CONTENT" in st.secrets:
    if not os.path.exists("google_credentials.json"):
        with open("google_credentials.json", "w") as f:
            f.write(st.secrets["GOOGLE_CREDENTIALS_CONTENT"])

# --- 1. CONFIGURATION ---
st.set_page_config(page_title="KinetiBridge ETL Pro", layout="wide", page_icon="🌐")

PADDLE_API_KEY = st.secrets.get("PADDLE_API_KEY", "")

# --- 2. AUTHENTICATION ---
authenticator = Authenticate(
    secret_credentials_path='google_credentials.json',
    cookie_name='kineti_auth_cookie',
    cookie_key='kinetibridge_secret_key', 
    redirect_uri="https://etl-tool-rep-4p2dkdcahg8ltcnnrukfge.streamlit.app/oauth2callback"
)

authenticator.check_authentification()

def is_subscribed(email):
    return True 

# --- 3. ETL ENGINE FUNCTIONS ---
def load_data(file_obj, name):
    ext = name.split('.')[-1].lower()
    if ext == 'csv': return pd.read_csv(file_obj)
    elif ext in ['xlsx', 'xls']: return pd.read_excel(file_obj)
    return None

def apply_visual_rules(df, rules, mapping_files):
    out_df = pd.DataFrame()
    for r in rules:
        target_name = r['name']
        mode = r['type']
        
        if mode == "Direct Map":
            out_df[target_name] = df[r['source']]
        
        elif mode == "Conditional":
            mask = pd.Series([True] * len(df))
            col, op, val = r['cond_col'], r['cond_op'], r['cond_val']
            try:
                comp_val = float(val) if str(val).replace('.','',1).isdigit() else val
                if op == ">": mask = df[col] > comp_val
                elif op == "<": mask = df[col] < comp_val
                elif op == "==": mask = df[col] == comp_val
            except: pass
            out_df[target_name] = mask.map({True: r['then'], False: r['else']})
            
        elif mode == "Lookup":
            m_df = mapping_files.get(r['map_name'])
            if m_df is not None:
                # Use mapping file logic
                lookup_dict = m_df.set_index(r['key_col'])[r['val_col']].to_dict()
                out_df[target_name] = df[r['in_col']].map(lookup_dict)
                
    return out_df

# --- 4. MAIN APP UI ---
def run_etl_app(email):
    st.title("🌐 KinetiBridge Visual ETL")
    st.sidebar.info(f"User: {email}")

    # Initialize session states
    if 'rules' not in st.session_state: st.session_state.rules = []
    if 'mapping_files' not in st.session_state: st.session_state.mapping_files = {}

    with st.sidebar:
        st.header("🔌 Source Data")
        uploaded_file = st.file_uploader("Upload Main File", type=['csv', 'xlsx'])
        
        st.divider()
        st.header("🗂️ Multi-Mapping Manager")
        
        # UI for adding multiple mapping files
        with st.expander("Add New Mapping Table"):
            m_file = st.file_uploader("Upload Lookup File", type=['csv', 'xlsx'], key="m_uploader")
            m_name = st.text_input("Mapping Name (Unique)", placeholder="e.g. region_codes")
            if st.button("💾 Save Mapping"):
                if m_file and m_name:
                    if m_name in st.session_state.mapping_files:
                        st.error("Name already exists!")
                    else:
                        st.session_state.mapping_files[m_name] = load_data(m_file, m_file.name)
                        st.success(f"Added {m_name}")
                else:
                    st.error("Missing file or name")

        # Display and manage current mappings
        if st.session_state.mapping_files:
            st.write("Current Mappings:")
            for m in list(st.session_state.mapping_files.keys()):
                col_m1, col_m2 = st.columns([3, 1])
                col_m1.caption(f"📍 {m}")
                if col_m2.button("🗑️", key=f"del_m_{m}"):
                    del st.session_state.mapping_files[m]
                    st.rerun()
        
        st.divider()
        if st.button("Logout"):
            authenticator.logout()
            st.rerun()

    if uploaded_file:
        df = load_data(uploaded_file, uploaded_file.name)
        cols = df.columns.tolist()

        tab1, tab2, tab3 = st.tabs(["🛠️ Rule Builder", "👁️ Preview Result", "🚀 Export"])

        with tab1:
            st.subheader("Define Transformation Rules")
            with st.expander("➕ Add New Column Rule", expanded=True):
                c1, c2, c3 = st.columns(3)
                new_col_name = c1.text_input("New Column Name")
                rule_type = c2.selectbox("Rule Type", ["Direct Map", "Conditional", "Lookup"])
                
                rule_data = {"name": new_col_name, "type": rule_type}
                
                if rule_type == "Direct Map":
                    rule_data['source'] = st.selectbox("Source Column", cols)
                elif rule_type == "Conditional":
                    r1, r2, r3 = st.columns(3)
                    rule_data['cond_col'] = r1.selectbox("If Column", cols)
                    rule_data['cond_op'] = r2.selectbox("Operator", [">", "<", "=="])
                    rule_data['cond_val'] = r3.text_input("Value")
                    r4, r5 = st.columns(2)
                    rule_data['then'] = r4.text_input("Then Result")
                    rule_data['else'] = r5.text_input("Else Result")
                elif rule_type == "Lookup":
                    if not st.session_state.mapping_files:
                        st.warning("⚠️ Please add a mapping table in the sidebar first.")
                    else:
                        rule_data['map_name'] = st.selectbox("Select Mapping Table", list(st.session_state.mapping_files.keys()))
                        rule_data['in_col'] = st.selectbox("Input Column (Main)", cols)
                        
                        # Dynamically get columns from the selected mapping table
                        target_m_df = st.session_state.mapping_files[rule_data['map_name']]
                        m_cols = target_m_df.columns.tolist()
                        
                        rule_data['key_col'] = st.selectbox("Match Key (Mapping Table)", m_cols)
                        rule_data['val_col'] = st.selectbox("Return Value (Mapping Table)", m_cols)

                if st.button("Add Rule"):
                    if new_col_name:
                        st.session_state.rules.append(rule_data)
                        st.success(f"Rule for {new_col_name} added.")
                    else:
                        st.error("Please enter a column name.")

            st.write("### Active Rules")
            for i, r in enumerate(st.session_state.rules):
                rc1, rc2 = st.columns([5, 1])
                rc1.info(f"**{r['name']}** ({r['type']})")
                if rc2.button("🗑️", key=f"del_r_{i}"):
                    st.session_state.rules.pop(i)
                    st.rerun()

        with tab2:
            if st.button("▶️ RUN TRANSFORMATION", type="primary"):
                st.session_state.result_df = apply_visual_rules(df, st.session_state.rules, st.session_state.mapping_files)
            
            if 'result_df' in st.session_state:
                st.dataframe(st.session_state.result_df, use_container_width=True)

        with tab3:
            if 'result_df' in st.session_state:
                csv = st.session_state.result_df.to_csv(index=False).encode('utf-8')
                st.download_button("💾 Download Result CSV", csv, "kinetibridge_output.csv")
    else:
        st.info("Please upload a file in the sidebar to begin.")

# --- 5. GATEKEEPER ---
if st.session_state.get('connected'):
    email = st.session_state['user_info'].get('email')
    if is_subscribed(email):
        run_etl_app(email)
    else:
        st.title("💳 Subscription Required")
        st.warning("Please subscribe to use KinetiBridge ETL.")
        st.markdown("[Upgrade to Pro](https://your-paddle-link.com)")
else:
    st.title("Welcome to KinetiBridge ETL")
    authenticator.login()