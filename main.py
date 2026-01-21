import streamlit as st
import pandas as pd
import json
import os
import paramiko
import requests # Required for Lemon Squeezy
from io import BytesIO, StringIO
from streamlit_google_auth import Authenticate

# --- 0. AUTH & CREDENTIALS ---
if "GOOGLE_CREDENTIALS_CONTENT" in st.secrets:
    if not os.path.exists("google_credentials.json"):
        with open("google_credentials.json", "w") as f:
            f.write(st.secrets["GOOGLE_CREDENTIALS_CONTENT"])

st.set_page_config(page_title="KinetiBridge Universal ETL", layout="wide", page_icon="🌉")

# --- AUTH SETUP ---
#redirect_uri = "http://localhost:8501/oauth2callback"  # <--- UNCOMMENT FOR LOCAL TESTING
redirect_uri = "https://etl-tool-rep-4p2dkdcahg8ltcnnrukfge.streamlit.app/oauth2callback" # <--- ACTIVE FOR CLOUD

authenticator = Authenticate(
    secret_credentials_path='google_credentials.json',
    cookie_name='kineti_auth_cookie',
    cookie_key='kinetibridge_secret_key', 
    redirect_uri=redirect_uri
)
authenticator.check_authentification()

# --- 1. LEMON SQUEEZY SUBSCRIPTION CHECKER ---
def check_lemon_status(email):
    """
    Checks if the user has an active subscription or a valid trial (10 days).
    """
    # Get secrets from Streamlit
    api_key = st.secrets.get("LEMON_API_KEY")
    store_id = st.secrets.get("LEMON_STORE_ID")
    
    # If no keys are set yet, we allow access (Safe for testing before you add secrets)
    if not api_key:
        return True 

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/vnd.api+json"
    }
    
    try:
        # Search for subscriptions specifically for this email and store
        url = f"https://api.lemonsqueezy.com/v1/subscriptions?filter[user_email]={email}&filter[store_id]={store_id}"
        response = requests.get(url, headers=headers)
        data = response.json()
        
        # Check the response data
        if data.get('data'):
            for sub in data['data']:
                status = sub['attributes']['status']
                # Lemon Squeezy logic: If status is 'active' (paid) or 'on_trial' (free 10 days), let them in.
                if status in ['active', 'on_trial']:
                    return True
    except Exception as e:
        # If API fails (e.g. connection issue), block access for security or print error
        print(f"License Error: {e}")
        pass
        
    return False

# --- 2. SMART DATA HANDLER (Original Full Version) ---
def smart_load(file_obj, filename, file_type_override=None):
    """
    Robust loader for CSV, Pipe, Excel, JSON, Parquet.
    """
    try:
        ext = filename.split('.')[-1].lower() if filename else ""
        
        if ext == 'csv' or file_type_override == 'csv':
            return pd.read_csv(file_obj)
        elif ext == 'txt' or file_type_override == 'pipe':
            return pd.read_csv(file_obj, sep='|') 
        elif ext in ['xlsx', 'xls'] or file_type_override == 'excel':
            return pd.read_excel(file_obj)
        elif ext == 'json' or file_type_override == 'json':
            return pd.read_json(file_obj)
        elif ext == 'parquet' or file_type_override == 'parquet':
            return pd.read_parquet(file_obj)
        else:
            try:
                return pd.read_csv(file_obj, sep=None, engine='python')
            except:
                st.error(f"❌ Unsupported file type: {filename}")
                return None
    except Exception as e:
        st.error(f"Error loading {filename}: {str(e)}")
        return None

# --- 3. SERVER CONNECTIVITY (Original Full Version) ---
def sftp_action(host, port, user, password, action, remote_path, local_data=None):
    """
    Handles both Extract (Get) and Load (Put) via SFTP
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=int(port), username=user, password=password)
        sftp = ssh.open_sftp()
        
        if action == "extract":
            with sftp.open(remote_path, "rb") as f:
                content = BytesIO(f.read())
                df = smart_load(content, remote_path)
            sftp.close()
            ssh.close()
            return df
            
        elif action == "load":
            with sftp.open(remote_path, "w") as f:
                csv_buffer = StringIO()
                local_data.to_csv(csv_buffer, index=False)
                f.write(csv_buffer.getvalue())
            sftp.close()
            ssh.close()
            return True
            
    except Exception as e:
        st.error(f"SFTP Connection Error: {str(e)}")
        st.caption("Tip: Ensure your server firewall allows connections from this IP.")
        return None

# --- 4. TRANSFORMATION ENGINE (Original Full Version) ---
def apply_rules_engine(main_df, rules, mapping_dfs):
    """
    Applies transformation logic.
    Uses pandas.eval() for complex AND/OR conditional logic.
    """
    out_df = pd.DataFrame() 
    
    if not main_df.empty:
        out_df = pd.DataFrame(index=main_df.index)

    for rule in rules:
        try:
            target = rule['name']
            r_type = rule['type']
            
            if r_type == "Direct Map":
                out_df[target] = main_df[rule['source']]
                
            elif r_type == "Conditional":
                # Advanced Eval Logic for AND/OR support
                expression = rule.get('expression')
                
                if expression:
                    try:
                        mask = main_df.eval(expression, engine='python')
                        out_df[target] = mask.map({True: rule['then'], False: rule['else']})
                    except Exception as eval_err:
                        st.error(f"Logic Error in column '{target}': {eval_err}")
                
            elif r_type == "Lookup":
                map_name = rule['map_name']
                if map_name in mapping_dfs:
                    m_df = mapping_dfs[map_name]
                    key_col = rule['key_col']
                    val_col = rule['val_col']
                    input_col = rule['in_col']
                    
                    # Robust lookup: Convert keys to string
                    lookup_dict = dict(zip(m_df[key_col].astype(str), m_df[val_col]))
                    out_df[target] = main_df[input_col].astype(str).map(lookup_dict)
                else:
                    st.warning(f"Mapping table '{map_name}' not found.")
                    
        except Exception as e:
            st.error(f"Rule Execution Failed ({rule.get('name')}): {e}")
            
    return out_df

# --- 5. LEGAL FOOTER ---
def show_legal_footer():
    st.markdown("---")
    with st.expander("📜 Legal Notices, Terms of Service & Privacy Policy", expanded=False):
        st.markdown("""
        ### 1. Terms of Service
        By using **KinetiBridge Universal ETL** ("the Service"), you agree to the following terms:
        * **"As Is" Basis:** The Service is provided "as is" without warranty of any kind, express or implied.
        * **No Liability:** The developers of KinetiBridge shall not be liable for any damages, data loss, or server issues.
        * **User Responsibility:** You are solely responsible for the data you upload and the server credentials you provide.
        
        ### 2. Privacy Policy & Data Handling
        * **Data Persistence:** We **do not** permanently store your uploaded files. All data is processed in temporary memory (RAM) and is discarded when your session ends or you reload the page.
        * **Server Credentials:** SFTP hostnames, usernames, and passwords entered in this application are **not saved** to any database.
        
        ### 3. Server Connectivity Disclaimer
        * **Firewalls:** This application runs on a dynamic cloud environment. To connect to your private SFTP servers, you may need to whitelist the dynamic IP of this instance.
        
        *Last Updated: 2026*
        """)

# --- 6. UI & STATE MANAGEMENT ---
def run_app(email):
    # ============================================================
    # 🔒 LIVE LEMON SQUEEZY GATE (10 DAY TRIAL)
    # ============================================================
    if not check_lemon_status(email):
        st.title("🔒 Start Your 10-Day Free Trial")
        st.info(f"Welcome, {email}. To access KinetiBridge Pro, please start your free trial.")
        
        # Get checkout link from secrets
        checkout_link = st.secrets.get("LEMON_CHECKOUT_URL", "#")
        
        # Auto-fill email in checkout link for better UX
        if "?" in checkout_link:
            checkout_link += f"&checkout[email]={email}"
        else:
            checkout_link += f"?checkout[email]={email}"
        
        st.markdown(f"""
        <a href="{checkout_link}" target="_blank" style="text-decoration:none;">
            <div style="background-color:#7047EB;color:white;padding:15px;text-align:center;border-radius:5px;font-weight:bold;font-size:18px;">
                🚀 Activate 10-Day Free Trial
            </div>
        </a>
        """, unsafe_allow_html=True)
        
        st.write("")
        st.caption("You will not be charged until the trial period ends. Cancel anytime.")
        
        if st.button("I have activated my trial, Refresh"):
            st.rerun()
            
        show_legal_footer()
        return  # <--- STOP HERE if not subscribed
    # ============================================================

    st.title("🚀 KinetiBridge Pro ETL")
    st.caption(f"Logged in as: {email} | Status: Active ✅")
    
    # Session State
    if 'rules' not in st.session_state: st.session_state.rules = []
    if 'data_inventory' not in st.session_state: st.session_state.data_inventory = {}
    if 'mapping_dfs' not in st.session_state: st.session_state.mapping_dfs = {}
    if 'temp_expr' not in st.session_state: st.session_state.temp_expr = ""

    # --- SIDEBAR: DATA CONNECTIONS ---
    with st.sidebar:
        st.header("1. Data Extraction")
        
        extract_mode = st.radio("Main Source Type", ["Upload Files", "Connect to Server (SFTP)"])
        
        if extract_mode == "Upload Files":
            uploaded_files = st.file_uploader("Upload Input Data", accept_multiple_files=True, type=['csv','txt','xlsx','json','parquet'])
            if uploaded_files:
                for f in uploaded_files:
                    st.session_state.data_inventory[f.name] = smart_load(f, f.name)
                st.success(f"Loaded {len(uploaded_files)} files.")

        elif extract_mode == "Connect to Server (SFTP)":
            st.markdown("##### 🔌 SFTP Connection")
            with st.expander("Server Config", expanded=True):
                s_host = st.text_input("Host IP/URL", key="s_host")
                s_port = st.text_input("Port", "22", key="s_port")
                s_user = st.text_input("Username", key="s_user")
                s_pwd = st.text_input("Password", type="password", key="s_pwd")
                s_path = st.text_input("Remote File Path", key="s_path")
                
                if st.button("Connect & Extract"):
                    if s_host and s_user and s_path:
                        with st.spinner("Extracting data..."):
                            df = sftp_action(s_host, s_port, s_user, s_pwd, "extract", s_path)
                            if df is not None:
                                fname = s_path.split("/")[-1]
                                st.session_state.data_inventory[fname] = df
                                st.success(f"Extracted: {fname}")
                    else:
                        st.error("Missing credentials")

        st.divider()
        st.header("2. Mapping Tables")
        
        map_source = st.radio("Mapping Source", ["Upload Lookups", "Download from Server (SFTP)"])
        
        if map_source == "Upload Lookups":
            m_files = st.file_uploader("Upload Files", accept_multiple_files=True, key="maps")
            if m_files:
                for mf in m_files:
                    m_key = mf.name.split('.')[0]
                    if m_key not in st.session_state.mapping_dfs:
                        st.session_state.mapping_dfs[m_key] = smart_load(mf, mf.name)
        
        elif map_source == "Download from Server (SFTP)":
            with st.expander("Mapping Server Config"):
                ms_host = st.text_input("Host", key="ms_host")
                ms_port = st.text_input("Port", "22", key="ms_port")
                ms_user = st.text_input("User", key="ms_user")
                ms_pwd = st.text_input("Pwd", type="password", key="ms_pwd")
                ms_path = st.text_input("Path", key="ms_path")
                
                if st.button("Load Mapping"):
                    if ms_host and ms_user and ms_path:
                        with st.spinner("Downloading Mapping..."):
                            m_df = sftp_action(ms_host, ms_port, ms_user, ms_pwd, "extract", ms_path)
                            if m_df is not None:
                                m_name = ms_path.split("/")[-1].split('.')[0]
                                st.session_state.mapping_dfs[m_name] = m_df
                                st.success(f"Mapping '{m_name}' Loaded")

        if st.session_state.mapping_dfs:
            st.info(f"Loaded {len(st.session_state.mapping_dfs)} mapping tables.")

        st.divider()
        if st.button("Logout"):
            authenticator.logout()
            st.rerun()

    # --- MAIN WORKSPACE ---
    if st.session_state.data_inventory:
        
        file_options = list(st.session_state.data_inventory.keys())
        selected_file = st.selectbox("Select Primary Data for Pipeline", file_options)
        main_df = st.session_state.data_inventory[selected_file]
        cols = main_df.columns.tolist()
        
        st.divider()
        
        col_imp, col_exp = st.columns([1, 1])
        with col_imp:
            uploaded_rules = st.file_uploader("📥 Import Pipeline (JSON)", type=['json'], label_visibility="collapsed")
            if uploaded_rules:
                try:
                    loaded = json.load(uploaded_rules)
                    st.session_state.rules = loaded
                    st.toast("Pipeline Loaded!", icon="✅")
                except:
                    st.error("Invalid JSON")

        with col_exp:
            if st.session_state.rules:
                rules_json = json.dumps(st.session_state.rules, indent=2)
                st.download_button("💾 Export Pipeline (JSON)", rules_json, "pipeline.json", "application/json", use_container_width=True)

        tab_build, tab_run, tab_load = st.tabs(["🏗️ Builder", "👁️ Preview", "🚀 Load / Export"])
        
        with tab_build:
            with st.expander("➕ Add Logic", expanded=True):
                c1, c2 = st.columns([1, 1])
                name = c1.text_input("New Column Name")
                r_type = c2.selectbox("Logic Type", ["Direct Map", "Conditional", "Lookup"])
                
                rule = {"name": name, "type": r_type}
                
                if r_type == "Direct Map":
                    rule['source'] = st.selectbox("Source Column", cols)
                
                elif r_type == "Conditional":
                    st.markdown("##### 🛠️ Formula Builder")
                    st.caption("Example: `(Amount > 500) & (Status == 'Active')`")
                    st.code(st.session_state.temp_expr if st.session_state.temp_expr else "(Empty)")
                    
                    cc1, cc2, cc3 = st.columns([2, 1, 2])
                    b_col = cc1.selectbox("Column", cols, key="b_col")
                    b_op = cc2.selectbox("Op", ["==", "!=", ">", "<", ">=", "<="], key="b_op")
                    b_val = cc3.text_input("Value", key="b_val")
                    
                    def format_val(val, df, col):
                        if df[col].dtype == 'object' and not (val.startswith('"') or val.startswith("'")):
                            return f"'{val}'"
                        return val

                    bc1, bc2, bc3 = st.columns(3)
                    if bc1.button("Add (AND)"):
                        safe_val = format_val(b_val, main_df, b_col)
                        segment = f"(`{b_col}` {b_op} {safe_val})"
                        st.session_state.temp_expr = f"{st.session_state.temp_expr} & {segment}" if st.session_state.temp_expr else segment
                        st.rerun()

                    if bc2.button("Add (OR)"):
                        safe_val = format_val(b_val, main_df, b_col)
                        segment = f"(`{b_col}` {b_op} {safe_val})"
                        st.session_state.temp_expr = f"{st.session_state.temp_expr} | {segment}" if st.session_state.temp_expr else segment
                        st.rerun()
                        
                    if bc3.button("Reset"):
                        st.session_state.temp_expr = ""
                        st.rerun()

                    rule['expression'] = st.session_state.temp_expr
                    ac4, ac5 = st.columns(2)
                    rule['then'] = ac4.text_input("Then Output")
                    rule['else'] = ac5.text_input("Else Output")

                elif r_type == "Lookup":
                    if not st.session_state.mapping_dfs:
                        st.warning("No mappings available.")
                    else:
                        m_names = list(st.session_state.mapping_dfs.keys())
                        rule['map_name'] = st.selectbox("Mapping Table", m_names)
                        rule['in_col'] = st.selectbox("Match Column (Main)", cols)
                        if rule['map_name']:
                            m_cols = st.session_state.mapping_dfs[rule['map_name']].columns.tolist()
                            rule['key_col'] = st.selectbox("Key Column (Map)", m_cols)
                            rule['val_col'] = st.selectbox("Value Column (Map)", m_cols)

                if st.button("Add Rule"):
                    if name:
                        if r_type == "Conditional" and not rule['expression']:
                            st.error("Formula cannot be empty")
                        else:
                            st.session_state.rules.append(rule)
                            st.session_state.temp_expr = ""
                            st.rerun()
                    else:
                        st.error("Name required")

            if st.session_state.rules:
                st.write("### Active Rules")
                for i, r in enumerate(st.session_state.rules):
                    rc1, rc2 = st.columns([5,1])
                    info_text = f"**{r['name']}** ({r['type']})"
                    if r['type'] == 'Conditional':
                        info_text += f" | `{r.get('expression')}`"
                    rc1.info(info_text)
                    if rc2.button("🗑️", key=f"del_{i}"):
                        st.session_state.rules.pop(i)
                        st.rerun()

        with tab_run:
            if st.button("▶️ RUN PIPELINE", type="primary"):
                st.session_state.result_df = apply_rules_engine(
                    main_df, st.session_state.rules, st.session_state.mapping_dfs
                )
            
            if 'result_df' in st.session_state:
                st.dataframe(st.session_state.result_df.head(100), use_container_width=True)

        with tab_load:
            st.header("Data Loading")
            load_mode = st.radio("Destination", ["Download File", "Push to Server (SFTP)"])
            
            if load_mode == "Download File":
                if 'result_df' in st.session_state:
                    csv_data = st.session_state.result_df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Download CSV", csv_data, "output.csv")
                else:
                    st.warning("Run Pipeline first.")
            
            elif load_mode == "Push to Server (SFTP)":
                st.markdown("##### 📤 SFTP Destination")
                lc1, lc2 = st.columns(2)
                d_host = lc1.text_input("Dest Host", key="d_host")
                d_user = lc2.text_input("Dest User", key="d_user")
                d_pwd = st.text_input("Dest Password", type="password", key="d_pwd")
                d_path = st.text_input("Dest Path (e.g. /home/out.csv)", key="d_path")
                
                if st.button("🚀 Push to Server"):
                    if 'result_df' in st.session_state and d_host:
                        success = sftp_action(d_host, "22", d_user, d_pwd, "load", d_path, st.session_state.result_df)
                        if success: st.success("Upload Successful!")
                    else:
                        st.error("Missing Data or Credentials")

    else:
        st.info("👈 Please Extract Data using the Sidebar to begin.")

    show_legal_footer()

# --- GATEKEEPER ---
if st.session_state.get('connected'):
    run_app(st.session_state['user_info'].get('email'))
else:
    st.title("Login to KinetiBridge")
    show_legal_footer()
    authenticator.login()