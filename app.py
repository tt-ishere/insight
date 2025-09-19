import requests
import streamlit as st
import pandas as pd
import os
import datetime
import plotly.express as px
import duckdb  # For SQL querying
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


# ==============================
# GOOGLE AUTH SETUP
# ==============================
CLIENT_ID = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI = st.secrets["google"]["redirect_uri"]

AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


# --- Google login URL ---
def login_with_google():
    return (
        f"{AUTHORIZATION_URL}"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid%20email%20profile"
    )


# --- Exchange code for token and fetch user info ---
def get_google_user_info(code):
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    # Using correct requests library
    r = requests.post(TOKEN_URL, data=data)
    tokens = r.json()

    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    user_info = requests.get(USERINFO_URL, headers=headers).json()
    return user_info

# ==============================
# CONFIGURATION
# ==============================
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

st.set_page_config(
    page_title="Insight",
    page_icon="🔍",
    layout="wide"
)

# ==============================
# GOOGLE LOGIN CHECK
# ==============================
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

# Use st.query_params (new stable API)
query_params = st.query_params
code = query_params.get("code", [None])[0] if isinstance(query_params.get("code"), list) else query_params.get("code")

# Handle redirect from Google with `code`
if code and st.session_state["user_email"] is None:
    user_info = get_google_user_info(code)
    st.session_state["user_email"] = user_info.get("email")

    # Clear query params after successful login
    st.query_params.clear()

# If not logged in, show centered login screen
if st.session_state["user_email"] is None:
    st.markdown(
        """
        <div style="text-align: center; margin-top: 100px;">
            <h1>🔍 Insight Login</h1>
            <p>Sign in with Google to continue</p>
            <a href="{login_url}">
                <button style="padding:10px 20px; font-size:18px; background-color:#4285F4; color:white; border:none; border-radius:5px;">
                    Login with Google
                </button>
            </a>
        </div>
        """.format(login_url=login_with_google()),
        unsafe_allow_html=True,
    )
    st.stop()

# Show app when logged in
st.sidebar.success(f"Logged in as {st.session_state['user_email']}")
st.write("Welcome to **Insight**! 🎉")

# ==============================
# LOGOUT FEATURE
# ==============================

# Logout button
if st.sidebar.button("🚪 Logout", use_container_width=True):
    # Clear session data
    for key in list(st.session_state.keys()):
        del st.session_state[key]

    st.success("You have been logged out.")
    st.stop()

# ==============================
# UTILITY FUNCTIONS
# ==============================
def list_uploaded_files():
    """Return a sorted list of uploaded files by last modified time."""
    return sorted(
        os.listdir(UPLOAD_DIR),
        key=lambda x: os.path.getmtime(os.path.join(UPLOAD_DIR, x)),
        reverse=True
    )

def delete_file(file_name):
    """Delete a file from uploads folder."""
    file_path = os.path.join(UPLOAD_DIR, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
        return True
    return False

# ==============================
# HELPER: Load Large CSV in Chunks
# ==============================
def load_large_csv(file_path, chunk_size=100000):
    """Read a large CSV file in chunks and combine into a single DataFrame."""
    chunks = []
    total_rows = 0

    # Count total lines to calculate progress
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        total_lines = sum(1 for line in f) - 1  # subtract header

    progress = st.sidebar.progress(0)

    for chunk in pd.read_csv(file_path, chunksize=chunk_size):
        chunks.append(chunk)
        total_rows += len(chunk)
        progress.progress(min(total_rows / total_lines, 1.0))

    return pd.concat(chunks, ignore_index=True)


# ==============================
# HELPER: Load File (CSV or Excel)
# ==============================
def load_file_as_df(file_name):
    """Load either CSV or Excel files efficiently."""
    file_path = os.path.join(UPLOAD_DIR, file_name)

    if file_name.lower().endswith(".csv"):
        st.sidebar.info("Loading CSV in chunks for better performance...")
        return load_large_csv(file_path, chunk_size=100000)
    elif file_name.lower().endswith(".xlsx"):
        return pd.read_excel(file_path, engine="openpyxl")
    else:
        st.sidebar.error("Unsupported file type!")
        return None

# ==============================
# HEADER
# ==============================
st.title("🔍 Insight")
st.markdown("### Turn your spreadsheets into **powerful insights** with dashboards, search, and SQL queries.")

# ==============================
# SIDEBAR - FILE UPLOAD & MANAGEMENT
# ==============================
st.sidebar.header("📂 Manage Your Files")

uploaded_file = st.sidebar.file_uploader(
    "Upload Excel or CSV file",
    type=["xlsx", "csv"]
)

if uploaded_file:
    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
    progress = st.sidebar.progress(0)  # Initialize progress bar
    chunk_size = 8192
    total_size = uploaded_file.size
    written = 0

    # Write the file in chunks
    with open(file_path, "wb") as f:
        while True:
            chunk = uploaded_file.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
            written += len(chunk)
            progress.progress(min(written / total_size, 1.0))  # Update progress bar

    # Success message AFTER the file is uploaded
    st.sidebar.success(f"✅ Upload complete: {uploaded_file.name}")
else:
    st.sidebar.info("📂 Please upload a file to get started")

# Sidebar - Select file
uploaded_files = list_uploaded_files()
selected_file = None
if uploaded_files:
    st.sidebar.subheader("Select a file to work with")
    selected_file = st.sidebar.selectbox("Choose a file", uploaded_files)

    # Delete button
    if st.sidebar.button("🗑 Delete Selected File", use_container_width=True, type="primary"):
        if delete_file(selected_file):
            st.sidebar.success(f"Deleted: {selected_file}")
            st.experimental_rerun()
        else:
            st.sidebar.error("Failed to delete file")

# ==============================
# MAIN APP TABS
# ==============================
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Dashboard", 
    "📁 Manage Files", 
    "🔍 Search Data", 
    "📝 SQL Query"
])

# ==============================
# TAB 1 - DASHBOARD
# ==============================
with tab1:
    st.subheader("📊 Dashboard Overview")
    if selected_file:
        st.write(f"### File: **{selected_file}**")

        df = load_file_as_df(selected_file)

        # --- Metrics ---
        total_rows = df.shape[0]
        total_columns = df.shape[1]

        col1, col2 = st.columns(2)
        col1.metric("Total Rows", total_rows)
        col2.metric("Total Columns", total_columns)

        st.markdown("### 📈 Visualization Options")

        # --- Detect column types ---
        numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
        categorical_cols = df.select_dtypes(exclude=['number']).columns.tolist()

        if len(numeric_cols) == 0 and len(categorical_cols) == 0:
            st.info("No suitable columns found for visualization.")
        else:
            chart_type = st.selectbox(
                "Choose Chart Type",
                ["Histogram", "Bar", "Line", "Pie"]
            )

            # -------- Bar / Line Charts --------
            if chart_type in ["Bar", "Line"]:
                x_axis = st.selectbox("Select X-axis", df.columns, key="x_axis")
                y_axis = st.selectbox("Select Y-axis", numeric_cols, key="y_axis")

                color_col = None
                if categorical_cols:
                    color_col = st.selectbox("Optional: Color by category", ["None"] + categorical_cols, key="color_col")
                    if color_col == "None":
                        color_col = None

                if chart_type == "Bar":
                    fig = px.bar(
                        df,
                        x=x_axis,
                        y=y_axis,
                        color=color_col,
                        title=f"{chart_type} Chart of {y_axis} by {x_axis}",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                else:  # Line chart
                    fig = px.line(
                        df,
                        x=x_axis,
                        y=y_axis,
                        color=color_col,
                        title=f"{chart_type} Chart of {y_axis} by {x_axis}",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )

                st.plotly_chart(fig, use_container_width=True)

            # -------- Histogram --------
            elif chart_type == "Histogram":
                chosen_col = st.selectbox("Select column for histogram", numeric_cols, key="hist_col")
                fig = px.histogram(
                    df,
                    x=chosen_col,
                    nbins=20,
                    color_discrete_sequence=px.colors.qualitative.Set3,
                    title=f"Distribution of {chosen_col}"
                )
                st.plotly_chart(fig, use_container_width=True)

            # -------- Pie Chart --------
            elif chart_type == "Pie":
                if categorical_cols and numeric_cols:
                    pie_labels = st.selectbox("Select category column for labels", categorical_cols, key="pie_labels")
                    pie_values = st.selectbox("Select numeric column for values", numeric_cols, key="pie_values")
                    
                    fig = px.pie(
                        df,
                        names=pie_labels,
                        values=pie_values,
                        title=f"Pie Chart of {pie_values} by {pie_labels}",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Need at least one categorical and one numeric column for a pie chart.")

    else:
        st.info("👈 Upload and select a file to view dashboard insights.")



# ==============================
# TAB 2 - MANAGE FILES
# ==============================
with tab2:
    st.subheader("📁 Uploaded Files")

    if uploaded_files:
        file_data = []
        for file_name in uploaded_files:
            file_path = os.path.join(UPLOAD_DIR, file_name)
            size_kb = round(os.path.getsize(file_path) / 1024, 2)
            last_modified = datetime.datetime.fromtimestamp(
                os.path.getmtime(file_path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            file_data.append([file_name, size_kb, last_modified])

        files_df = pd.DataFrame(file_data, columns=["File Name", "Size (KB)", "Last Modified"])
        st.dataframe(files_df, use_container_width=True)
    else:
        st.info("No files uploaded yet.")

# ==============================
# TAB 3 - SEARCH DATA
# ==============================
with tab3:
    st.subheader("🔍 Search Uploaded Data")

    if selected_file:
        df = load_file_as_df(selected_file)
        st.caption(f"Rows: {df.shape[0]} | Columns: {df.shape[1]}")

        # ---- Search area ----
        search_col = st.selectbox("Select column to search", df.columns)
        search_value = st.text_input("Enter value to search")

        filtered_df = df
        if search_value:
            filtered_df = df[df[search_col].astype(str).str.contains(search_value, case=False, na=False)]

            def highlight(val):
                if search_value.lower() in str(val).lower():
                    return 'background-color: yellow'
                return ''
            st.dataframe(filtered_df.style.applymap(highlight), use_container_width=True)

            st.success(f"Found {len(filtered_df)} matching rows.")
        else:
            st.dataframe(df, use_container_width=True)

        # ---- Download filtered results ----
        st.markdown("### 📥 Download Options")
        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                "Download Filtered Results (CSV)",
                data=filtered_df.to_csv(index=False).encode("utf-8"),
                file_name=f"{selected_file.split('.')[0]}_filtered.csv",
                mime="text/csv"
            )

        with col2:
            with open(os.path.join(UPLOAD_DIR, selected_file), "rb") as f:
                st.download_button(
                    "Download Full File",
                    data=f,
                    file_name=selected_file,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
    else:
        st.info("👈 Upload and select a file to start searching.")

# ==============================
# TAB 4 - SQL QUERY
# ==============================
with tab4:
    st.subheader("📝 Run SQL Queries on Data")

    if selected_file:
        df = load_file_as_df(selected_file)
        st.caption("Use SQL to query your Excel data. Example: `SELECT * FROM data LIMIT 10`")

        query = st.text_area("Enter your SQL query:", "SELECT * FROM data LIMIT 10")

        if st.button("Run Query", type="primary"):
            try:
                # Register dataframe as table
                duckdb.register("data", df)
                result = duckdb.query(query).to_df()

                st.write("### Query Results")
                st.dataframe(result, use_container_width=True)

                # Allow downloading results
                st.download_button(
                    "Download Query Results (CSV)",
                    data=result.to_csv(index=False).encode("utf-8"),
                    file_name="query_results.csv",
                    mime="text/csv"
                )

            except Exception as e:
                st.error(f"❌ Query failed: {e}")
    else:
        st.info("👈 Upload and select a file to run queries.")

# ==============================
# FOOTER (Centered)
# ==============================
st.markdown("---")
st.markdown(
    "<div style='text-align: center;'>🔍 Insight - Built with ❤️ by TT</div>",
    unsafe_allow_html=True
)
