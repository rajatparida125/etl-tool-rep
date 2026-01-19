import streamlit as st
import pandas as pd
import json
import requests
import os
import paramiko
from io import BytesIO
from streamlit_google_auth import Authenticate

# --- 0. AUTH & CREDENTIALS ---
if "GOOGLE_CREDENTIALS_CONTENT" in st.secrets:
    if not os.path.exists("google_credentials.json"):
        with open("google_credentials.json", "w") as f:
            f.write(st.secrets["GOOGLE_CREDENTIALS_CONTENT"])

st.set_page_config(page_title="KinetiBridge Pro ETL", layout="wide", page_icon="🌐")

authenticator = Authenticate(
    secret_credentials_path='google_credentials.json',
    cookie_name='kineti_auth_cookie',
    cookie_key='kinetibridge_secret_key', 
    redirect_uri="https://etl-tool-rep-4p2dkdcahg8ltcnnrukfge.streamlit.app/oauth2callback"
)
authenticator.check_authentification()

# --- 1. CORE ETL UTILITIES ---
def smart_load(file_source, filename):
    ext = filename.split('.')[-1].lower()
    try:
        if ext == 'csv': return pd.read_csv(file_source)
        if ext in ['xlsx', 'xls']: return pd.read_excel(file_source)
        if ext == 'json': return pd.read_json(file_source)
    except Exception as e:
        st.error(f"Error loading {filename}: {e}")
    return None

def apply_rules(df, rules, mappings):
    out_df = pd.DataFrame()
    for r in rules:
        try:
            name = r['name']
            if r['type'] == "Direct Map":
                out_df[name] = df[r['source']]
            elif r['type'] == "Lookup":
                m_df = mappings.get(r['map_name'])
                if m_df is not None:
                    lookup = m_df.set_index(r['key_col'])[r['val_col']].to_dict()
                    out_df[name] = df[r['in_col']].map(lookup)
            elif r['type'] == "Conditional":
                # Basic conditional logic
                c, op, v = r['cond_col'], r['cond_op'], r['cond_val']
                if op == ">": mask = df[c] > float(v)
                elif op == "<": mask = df[c] < float(v)
                else: mask = df[c] == v
                out_df[name] = mask.map({True: r['then'], False: r['else']})
        except Exception as e:
            st.warning(f"Skipping rule '{r.get('name')}': {e}")
    return out_df

# --- 2. MAIN APPLICATION UI ---
def run_app(email):
    st.title("🚀 KinetiBridge Pro ETL")
    
    # Persistent State
    if 'rules' not in st.session_state: st.session_state.rules = []
    if 'input_dfs' not in st.session_state: st.session_state.input_dfs = {}

    with st.sidebar:
        st.header("📥 Data Sources")
        uploaded_files = st.file_uploader("Extract Files (CSV, XLSX, JSON)", accept_multiple_files=True)
        if uploaded_files:
            for f in uploaded_files:
                st.session_state.input_dfs[f.name] = smart_load(f, f.name)
        
        st.divider()
        st.header("💾 Pipeline Management")
        
        # SAVE RULES
        if st.session_state.rules:
            pipeline_json = json.dumps(st.session_state.rules, indent=2)
            st.download_button("📂 Export Pipeline (JSON)", pipeline_json, "pipeline.json", "application/json")
        
        # LOAD RULES
        loaded_pipeline = st.file_uploader("📥 Import Pipeline", type=['json'])
        if loaded_pipeline:
            st.session_state.rules = json.load(loaded_pipeline)
            st.success("Pipeline loaded!")
            
        st.divider()
        if st.button("Logout"):
            authenticator.logout()
            st.rerun()

    if st.session_state.input_dfs:
        main_source = st.selectbox("Select Primary File", list(st.session_state.input_dfs.keys()))
        df = st.session_state.input_dfs[main_source]
        cols = df.columns.tolist()

        t_build, t_preview, t_export = st.tabs(["🏗️ Builder", "🔭 Preview", "🚀 Load"])
        
        with t_build:
            with st.expander("➕ Add Logic", expanded=True):
                c1, c2 = st.columns(2)
                r_name = c1.text_input("New Column Name")
                r_type = c2.selectbox("Type", ["Direct Map", "Lookup", "Conditional"])
                
                rule = {"name": r_name, "type": r_type}
                if r_type == "Direct Map":
                    rule['source'] = st.selectbox("Source", cols)
                elif r_type == "Lookup":
                    rule['map_name'] = st.selectbox("Map Table", list(st.session_state.input_dfs.keys()))
                    rule['in_col'] = st.selectbox("Input Key", cols)
                    m_cols = st.session_state.input_dfs[rule['map_name']].columns.tolist()
                    rule['key_col'] = st.selectbox("Map Key", m_cols)
                    rule['val_col'] = st.selectbox("Map Value", m_cols)
                
                if st.button("Add Rule"):
                    st.session_state.rules.append(rule)
                    st.rerun()

            st.write("Current Rules:")
            for i, r in enumerate(st.session_state.rules):
                rc1, rc2 = st.columns([5,1])
                rc1.info(f"{r['name']} ({r['type']})")
                if rc2.button("🗑️", key=f"del_{i}"):
                    st.session_state.rules.pop(i)
                    st.rerun()

        with t_preview:
            if st.button("▶️ EXECUTE PIPELINE"):
                st.session_state.result_df = apply_rules(df, st.session_state.rules, st.session_state.input_dfs)
            if 'result_df' in st.session_state:
                st.dataframe(st.session_state.result_df)

        with t_export:
            if 'result_df' in st.session_state:
                csv = st.session_state.result_df.to_csv(index=False).encode('utf-8')
                st.download_button("💾 Download Results", csv, "output.csv")
    else:
        st.info("Upload your source files to begin.")

# --- 3. GATEKEEPER ---
if st.session_state.get('connected'):
    run_app(st.session_state['user_info'].get('email'))
else:
    st.title("Welcome to KinetiBridge")
    authenticator.login()