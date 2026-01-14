import streamlit as st
import pandas as pd
import json
import io
import os

st.set_page_config(page_title="Advanced ETL v2.2", layout="wide")

st.title("🚀 Advanced ETL Tool")
st.markdown("**Direct Copy + Lookup + Conditional Logic**")

EXAMPLES = {
    "1. Direct Copy": '''{
  "output_columns": [
    {"name": "OrderID", "source": "order_id"},
    {"name": "Amount", "source": "amount"},
    {"name": "Priority", "source": "priority"}
  ]
}''',
    
    "2. Lookup Example": '''{
  "output_columns": [
    {"name": "OrderID", "source": "order_id"},
    {
      "name": "ProductName",
      "lookup": {
        "mapping_file": "product_mapping",
        "input_col": "product_code",
        "key_col": "product_code",
        "target_col": "product_name"
      }
    },
    {"name": "Amount", "source": "amount"}
  ]
}''',
    
    "3. ALL 3 Types": '''{
  "output_columns": [
    {"name": "OrderID", "source": "order_id"},
    {
      "name": "ProductName",
      "lookup": {
        "mapping_file": "product_mapping",
        "input_col": "product_code",
        "key_col": "product_code", 
        "target_col": "product_name"
      }
    },
    {
      "name": "CustomerTier",
      "condition": {
        "if": [
          {"input_col": "amount", "operator": ">", "value": 200}
        ],
        "then": "Premium",
        "else": "Standard"
      }
    }
  ]
}'''
}

# Sidebar - ROBUST file handling
with st.sidebar:
    st.header("📁 Upload Files")
    
    # Input file with validation
    raw_file = st.file_uploader("**Input File**", type=['csv', 'xlsx'], key="raw")
    
    if raw_file:
        # Check file size & content FIRST
        file_size = len(raw_file.getvalue())
        st.info(f"📊 File size: {file_size/1000:.1f} KB")
        
        if file_size == 0:
            st.error("❌ File is empty!")
        else:
            st.success("✅ File loaded OK")
    
    # Mapping files
    mapping_files = {}
    num_mappings = st.number_input("Mapping files", 0, 5, 1, key="num_maps")
    
    for i in range(num_mappings):
        with st.expander(f"Mapping {i+1}"):
            uploaded_file = st.file_uploader(f"File {i+1}", type=['csv', 'xlsx'], key=f"file_{i}")
            name = st.text_input("Name (e.g: product_mapping)", value=f"mapping_{i+1}", key=f"name_{i}")
            
            if uploaded_file and name:
                try:
                    # Read with error handling
                    if uploaded_file.name.endswith('.csv'):
                        temp_df = pd.read_csv(uploaded_file, nrows=5)
                    else:
                        temp_df = pd.read_excel(uploaded_file, nrows=5)
                    
                    mapping_files[name] = temp_df
                    st.success(f"✅ **{name}**: {len(temp_df)} rows, {len(temp_df.columns)} cols")
                    
                except pd.errors.EmptyDataError:
                    st.error(f"❌ **{name}**: Empty or bad format")
                except Exception as e:
                    st.error(f"❌ **{name}**: {str(e)}")

# Main page
col1, col2 = st.columns(2)

with col1:
    st.header("📝 JSON Logic")
    
    # Show input columns if file valid
    input_columns = []
    if raw_file and len(raw_file.getvalue()) > 0:
        try:
            raw_buffer = raw_file.read()
            raw_file.seek(0)  # Reset file pointer
            if raw_file.name.endswith('.csv'):
                df_preview = pd.read_csv(io.StringIO(raw_buffer.decode('utf-8')))
            else:
                df_preview = pd.read_excel(raw_file)
            
            input_columns = df_preview.columns.tolist()
            st.info(f"**Input columns**: {', '.join(input_columns)}")
        except:
            st.warning("⚠️ Cannot preview input columns")
    
    example_name = st.selectbox("📋 Load example", ["Custom"] + list(EXAMPLES.keys()), key="example")
    
    # Safe default JSON
    safe_json = '''{
  "output_columns": [
    {"name": "Output1", "source": "order_id"}
  ]
}'''
    
    json_text = EXAMPLES.get(example_name.replace(" ", "_").lower(), safe_json)
    json_text = st.text_area("**JSON Config**", json_text, height=400, key="json_main")

with col2:
    st.header("📖 Examples")
    for title, ex in EXAMPLES.items():
        with st.expander(title):
            st.code(ex, language="json")

# BULLETPROOF ETL EXECUTION
if st.button("🚀 **RUN ETL**", type="primary") and raw_file:
    try:
        # SAFEST file reading
        raw_buffer = raw_file.read()
        raw_file.seek(0)
        
        if len(raw_buffer) == 0:
            st.error("❌ Input file is empty!")
            st.stop()
        
        if raw_file.name.endswith('.csv'):
            df = pd.read_csv(io.StringIO(raw_buffer.decode('utf-8')))
        else:
            df = pd.read_excel(raw_file)
        
        if df.empty:
            st.error("❌ No data found in input file!")
            st.stop()
        
        st.success(f"✅ Loaded **{len(df)} rows**, **{len(df.columns)} columns**")
        st.dataframe(df.head(), height=200)
        
        config = json.loads(json_text)
        result_df = pd.DataFrame()
        errors = []
        
        # Process each output column SAFELY
        for col_config in config.get("output_columns", []):
            col_name = col_config.get("name", f"col_{len(result_df.columns)}")
            
            try:
                # 1. DIRECT COPY
                if "source" in col_config:
                    source_col = col_config["source"]
                    if source_col in df.columns:
                        result_df[col_name] = df[source_col]
                        st.success(f"📋 **{col_name}** ← `{source_col}`")
                    else:
                        result_df[col_name] = f"Missing: {source_col}"
                        errors.append(f"❌ {col_name}: Column '{source_col}' not found")
                
                # 2. LOOKUP
                elif "lookup" in col_config:
                    lookup = col_config["lookup"]
                    mapping_name = lookup["mapping_file"]
                    
                    if mapping_name in mapping_files:
                        mapping_df = mapping_files[mapping_name]
                        input_col = lookup["input_col"]
                        key_col = lookup["key_col"]
                        target_col = lookup["target_col"]
                        
                        if (input_col in df.columns and 
                            key_col in mapping_df.columns and 
                            target_col in mapping_df.columns):
                            lookup_dict = mapping_df.set_index(key_col)[target_col].to_dict()
                            result_df[col_name] = df[input_col].map(lookup_dict).fillna(df[input_col])
                            st.success(f"🔍 **{col_name}** ← {mapping_name} ({key_col}→{target_col})")
                        else:
                            result_df[col_name] = "LOOKUP_ERROR"
                            errors.append(f"❌ {col_name}: Invalid lookup columns")
                    else:
                        result_df[col_name] = f"No: {mapping_name}"
                        errors.append(f"❌ {col_name}: Mapping '{mapping_name}' missing")
                
                # 3. CONDITIONAL
                elif "condition" in col_config:
                    cond = col_config["condition"]
                    mask = pd.Series([True] * len(df), index=df.index)
                    
                    for if_cond in cond.get("if", []):
                        input_col = if_cond["input_col"]
                        if input_col in df.columns:
                            col_val = df[input_col]
                            op = if_cond["operator"]
                            val = if_cond["value"]
                            
                            if op == "=": mask &= (col_val == val)
                            elif op == ">": mask &= (col_val > val)
                            elif op == "<": mask &= (col_val < val)
                            elif op == ">=": mask &= (col_val >= val)
                            elif op == "<=": mask &= (col_val <= val)
                    
                    result_df[col_name] = mask.map({True: cond["then"], False: cond["else"]})
                    st.success(f"🧠 **{col_name}**: Conditional applied")
            
            except Exception as col_error:
                result_df[col_name] = f"Error"
                errors.append(f"❌ {col_name}: {str(col_error)}")
        
        # FINAL RESULTS
        st.header("✅ **Transformation Results**")
        st.dataframe(result_df, use_container_width=True)
        
        if errors:
            st.error("**Issues:**\n" + "\n".join(errors[:3]))
        
        # Download
        csv_buffer = io.StringIO()
        result_df.to_csv(csv_buffer, index=False)
        st.download_button("💾 **Download CSV**", csv_buffer.getvalue(), "etl_result.csv", type="primary")
        
    except pd.errors.EmptyDataError:
        st.error("❌ **File empty** - No data/columns found!")
    except UnicodeDecodeError:
        st.error("❌ **File encoding** - Try saving as UTF-8 CSV")
    except Exception as e:
        st.error(f"❌ **Error**: {str(e)}")

st.markdown("---")
st.caption("**Logic Types**: `source` (copy), `lookup` (mapping), `condition` (if/then)")
