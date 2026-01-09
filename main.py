import streamlit as st
import pandas as pd
import io

st.set_page_config(page_title="Simple ETL Tool", layout="wide")

st.title("🔄 Simple ETL Tool")
st.markdown("Upload raw data + mapping → configure → download transformed CSV")

# Step 1: File uploads
col1, col2 = st.columns(2)
with col1:
    raw_file = st.file_uploader("📁 Upload raw CSV/Excel", type=['csv', 'xlsx', 'xls'], key="raw")
with col2:
    mapping_file = st.file_uploader("🗺️ Upload mapping file (optional)", type=['csv', 'xlsx', 'xls'], key="mapping")

if raw_file is not None:
    # Read raw data
    if raw_file.name.endswith('.csv'):
        df = pd.read_csv(raw_file)
    else:
        df = pd.read_excel(raw_file)
    
    st.success(f"✅ Loaded {len(df)} rows, {len(df.columns)} columns")
    st.dataframe(df.head(10), use_container_width=True)

    # Show mapping preview if uploaded
    mapping_df = None
    if mapping_file is not None:
        if mapping_file.name.endswith('.csv'):
            mapping_df = pd.read_csv(mapping_file)
        else:
            mapping_df = pd.read_excel(mapping_file)
        st.success(f"✅ Mapping loaded: {len(mapping_df)} rows")
        st.dataframe(mapping_df.head(), use_container_width=True)

    # Step 2: Configure transforms
    st.subheader("⚙️ Configure Output Columns")
    st.markdown("**For each output column:**")
    
    output_columns = []
    num_output_cols = st.number_input("Number of output columns", min_value=1, max_value=10, value=3, key="num_cols")
    
    for i in range(num_output_cols):
        with st.expander(f"Output Column {i+1}"):
            col_name = st.text_input(f"Output column name", value=f"col_{i+1}", key=f"name_{i}")
            
            # Source column selection
            source_col = st.selectbox(f"Source column", options=['None'] + list(df.columns.tolist()), key=f"source_{i}")
            
            # Mapping (if mapping file exists)
            mapping_choice = "None"
            if mapping_df is not None:
                mapping_choice = st.selectbox("Apply mapping?", 
                                            options=["None"] + list(mapping_df.columns),
                                            key=f"mapping_{i}")
            
            output_columns.append({
                'name': col_name,
                'source': source_col,
                'mapping_key': mapping_choice if mapping_choice != "None" else None
            })
    
    # Step 3: Transform button
    if st.button("🚀 Run Transform", type="primary", key="transform"):
        result_df = pd.DataFrame()
        
        for config in output_columns:
            if config['source'] != 'None':
                # Copy source column
                result_df[config['name']] = df[config['source']]
                
                # Apply mapping if specified
                if config['mapping_key'] and mapping_df is not None:
                    # Better mapping logic - find next column after key as target
                    key_col_idx = list(mapping_df.columns).index(config['mapping_key'])
                    if key_col_idx + 1 < len(mapping_df.columns):
                        target_col = mapping_df.columns[key_col_idx + 1]
                        map_dict = mapping_df.set_index(config['mapping_key'])[target_col].to_dict()
                        result_df[config['name']] = result_df[config['name']].map(map_dict).fillna(result_df[config['name']])
                        st.info(f"✅ Mapped {config['name']} using {config['mapping_key']} → {target_col}")
                    else:
                        st.warning(f"No target column found after {config['mapping_key']}")
        
        # Show result
        st.success(f"✅ Transform complete! {len(result_df)} rows, {len(result_df.columns)} columns")
        st.dataframe(result_df.head(10), use_container_width=True)
        
        # Download
        csv_buffer = io.StringIO()
        result_df.to_csv(csv_buffer, index=False)
        st.download_button(
            "📥 Download CSV",
            csv_buffer.getvalue(),
            "transformed_data.csv",
            "text/csv",
            key="download"
        )
        
        # Log
        st.subheader("📋 Transform Log")
        st.text(f"Created {len(output_columns)} output columns")
        if mapping_file:
            st.text("Applied mapping from uploaded file")
