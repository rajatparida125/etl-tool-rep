import streamlit as st
import pandas as pd
import json
import io
import os
from sqlalchemy import create_engine

# --- CONFIG & EXAMPLES ---
st.set_page_config(page_title="DataBridge ETL Pro v3.0", layout="wide")

EXAMPLES = {
    "1. Direct Copy": '{\n  "output_columns": [\n    {"name": "OrderID", "source": "order_id"}\n  ]\n}',
    "2. Lookup Example": '{\n  "output_columns": [\n    {\n      "name": "ProductName",\n      "lookup": {\n        "mapping_file": "product_mapping",\n        "input_col": "product_code",\n        "key_col": "product_code",\n        "target_col": "product_name"\n      }\n    }\n  ]\n}',
    "3. Conditional Tiering": '{\n  "output_columns": [\n    {\n      "name": "Tier",\n      "condition": {\n        "if": [{"input_col": "amount", "operator": ">", "value": 200}],\n        "then": "Premium",\n        "else": "Standard"\n      }\n    }\n  ]\n}'
}

# --- HELPER FUNCTIONS ---
def load_data(file_obj, name):
    """Supports CSV, Excel, Parquet, JSON, and XML"""
    ext = name.split('.')[-1].lower()
    if ext == 'csv': return pd.read_csv(file_obj)
    elif ext in ['xlsx', 'xls']: return pd.read_excel(file_obj)
    elif ext == 'parquet': return pd.read_parquet(file_obj)
    elif ext == 'json': return pd.read_json(file_obj)
    elif ext == 'xml': return pd.read_xml(file_obj)
    return None

# --- SIDEBAR: CONNECTORS ---
mapping_files = {}

with st.sidebar:
    st.title("🔌 Connectors")
    
    source_mode = st.radio("Data Source", ["Manual Upload", "SQL Database"])
    
    input_df = None
    if source_mode == "Manual Upload":
        uploaded_main = st.file_uploader("Upload Main File", type=['csv', 'xlsx', 'parquet', 'json', 'xml'])
        if uploaded_main:
            input_df = load_data(uploaded_main, uploaded_main.name)
    else:
        db_conn = st.text_input("Conn String", placeholder="sqlite:///data.db or postgresql://...")
        query = st.text_area("SQL Query", "SELECT * FROM table")
        if st.button("Fetch Data"):
            engine = create_engine(db_conn)
            input_df = pd.read_sql(query, engine)

    st.divider()
    st.header("🗂️ Lookup Mappings")
    num_maps = st.number_input("Add Mappings", 0, 5, 1)
    for i in range(num_maps):
        with st.expander(f"Mapping {i+1}"):
            m_file = st.file_uploader(f"File {i+1}", type=['csv', 'xlsx'], key=f"m_up_{i}")
            m_name = st.text_input("Internal Name", value=f"mapping_{i+1}", key=f"m_nm_{i}")
            if m_file:
                mapping_files[m_name] = load_data(m_file, m_file.name)

# --- MAIN UI ---
st.title("🌐 DataBridge ETL Pro")

if input_df is not None:
    tab_editor, tab_preview, tab_export, tab_tutorial = st.tabs(["🛠️ Logic Editor", "👁️ Preview", "🚀 Export/Load", "📖 Help"])

    with tab_editor:
        col_json, col_info = st.columns([2, 1])
        with col_info:
            st.info(f"**Available Columns:**\n{', '.join(input_df.columns.tolist())}")
            ex_choice = st.selectbox("Load Example", ["Custom"] + list(EXAMPLES.keys()))
            json_init = EXAMPLES.get(ex_choice, '{\n  "output_columns": []\n}')
        
        json_text = st.text_area("JSON Configuration", json_init, height=400)

    # --- THE ETL ENGINE (Your Core Logic) ---
    result_df = pd.DataFrame()
    if st.button("▶️ RUN TRANSFORMATION", type="primary"):
        try:
            config = json.loads(json_text)
            for col_config in config.get("output_columns", []):
                name = col_config.get("name", "new_col")
                
                # 1. Source Copy
                if "source" in col_config:
                    src = col_config["source"]
                    result_df[name] = input_df[src] if src in input_df.columns else "ERROR"
                
                # 2. Lookup logic
                elif "lookup" in col_config:
                    lk = col_config["lookup"]
                    m_df = mapping_files.get(lk["mapping_file"])
                    if m_df is not None:
                        lookup_dict = m_df.set_index(lk["key_col"])[lk["target_col"]].to_dict()
                        result_df[name] = input_df[lk["input_col"]].map(lookup_dict)
                
                # 3. Condition Logic
                elif "condition" in col_config:
                    cond = col_config["condition"]
                    mask = pd.Series([True] * len(input_df))
                    for if_c in cond.get("if", []):
                        val = input_df[if_c["input_col"]]
                        op, v = if_c["operator"], if_c["value"]
                        if op == ">": mask &= (val > v)
                        elif op == "<": mask &= (val < v)
                        elif op == "=": mask &= (val == v)
                    result_df[name] = mask.map({True: cond["then"], False: cond["else"]})
            
            st.session_state['transformed_data'] = result_df
            st.success("Transformation Successful!")
        except Exception as e:
            st.error(f"Logic Error: {e}")

    with tab_preview:
        if 'transformed_data' in st.session_state:
            st.dataframe(st.session_state['transformed_data'], use_container_width=True)
        else:
            st.warning("Run the transformation first!")

    with tab_export:
        if 'transformed_data' in st.session_state:
            exp_col1, exp_col2 = st.columns(2)
            with exp_col1:
                st.subheader("Download")
                csv = st.session_state['transformed_data'].to_csv(index=False).encode('utf-8')
                st.download_button("💾 Download CSV", csv, "output.csv", "text/csv")
            
            with exp_col2:
                st.subheader("Push to Server")
                dest_conn = st.text_input("Dest Conn String", key="dest_conn")
                dest_table = st.text_input("Target Table Name")
                if st.button("🚀 Push to Database"):
                    engine = create_engine(dest_conn)
                    st.session_state['transformed_data'].to_sql(dest_table, engine, if_exists='replace')
                    st.success("Data pushed successfully!")

    with tab_tutorial:
        st.markdown("### How to use DataBridge ETL")
        st.video("https://www.youtube.com/watch?v=dQw4w9WgXcQ") # Replace with your tutorial
        st.markdown("""
        1. **Connect**: Sidebar upload or SQL string.
        2. **Configure**: Use JSON to map columns.
        3. **Enrich**: Upload mapping files for lookups.
        4. **Export**: Send to a database or download.
        """)
else:
    st.warning("Please upload a file or connect to a database in the sidebar.")