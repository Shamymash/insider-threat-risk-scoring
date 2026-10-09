import streamlit as st
import pandas as pd
import plotly.express as px

# 1. PAGE CONFIGURATION
st.set_page_config(page_title="Insider Threat Monitor", layout="wide")

# 2. LOAD DATA (Bulletproof Version)
@st.cache_data
def load_data():
    try:
        # Load the file
        df = pd.read_csv("Capstone_Ready_Data_Final.csv")
        
        # --- THE FIX: FORCE RENAME FIRST COLUMN ---
        # No matter what the first column is named (blank, BOM, etc.), 
        # we rename it to 'user' because we know it's the user column.
        df.rename(columns={df.columns[0]: 'user'}, inplace=True)
        
        # Lowercase all other columns to be safe
        df.rename(columns=lambda x: str(x).lower().strip(), inplace=True)

        # Ensure date is recognized
        if 'day' in df.columns:
            df['day'] = pd.to_datetime(df['day'])
            
        return df

    except Exception as e:
        st.error(f"❌ Critical Error loading file: {e}")
        st.stop()

try:
    df = load_data()
    
    # DEBUG: Double check columns exist
    if 'user' not in df.columns:
        st.error(f"❌ Error: Still cannot find 'user' column. Columns found: {list(df.columns)}")
        st.stop()
        
except FileNotFoundError:
    st.error("❌ Error: Could not find 'Capstone_Ready_Data_Final.csv'. Make sure it is in the same folder as this script!")
    st.stop()

# 3. SIDEBAR: FILTERS
st.sidebar.title("🛡️ Security Ops Center")
st.sidebar.markdown("---")

# Filter: Show only Risky Users?
show_only_risky = st.sidebar.checkbox("Show Only High Risk Users (>30)", value=True)

if show_only_risky:
    # Filter for users who have EVER had a high risk score
    # Check if risk_score exists
    if 'risk_score' in df.columns:
        risky_users = df[df['risk_score'] > 30]['user'].unique()
        filtered_df = df[df['user'].isin(risky_users)]
    else:
        st.warning("'risk_score' column missing. Showing all users.")
        filtered_df = df
else:
    filtered_df = df

# Select Specific User
if filtered_df.empty:
    st.warning("No users found matching the criteria.")
    st.stop()

user_list = filtered_df['user'].unique()
selected_user = st.sidebar.selectbox("Select Employee ID", user_list)

# 4. MAIN DASHBOARD FOR SELECTED USER
user_data = df[df['user'] == selected_user].sort_values('day')

# Handle missing risk score if strictly necessary
if 'risk_score' in user_data.columns:
    current_risk = user_data['risk_score'].max()
else:
    current_risk = 0

# Title Section
col_header, col_score = st.columns([3, 1])
with col_header:
    st.title(f"User Profile: {selected_user}")
    st.markdown("**Department:** Investment Banking (Simulated)")

with col_score:
    if current_risk > 70:
        st.error(f"🚨 CRITICAL RISK: {current_risk}")
    elif current_risk > 30:
        st.warning(f"⚠️ High Risk: {current_risk}")
    else:
        st.success(f"✅ Low Risk: {current_risk}")

st.markdown("---")

# 5. KEY METRICS ROWS
kpi1, kpi2, kpi3, kpi4 = st.columns(4)

total_logins = user_data['total_logins'].sum() if 'total_logins' in user_data.columns else 0
late_logins = user_data['after_hours_logins'].sum() if 'after_hours_logins' in user_data.columns else 0
usb_count = user_data['usb_connects'].sum() if 'usb_connects' in user_data.columns else 0

# Check if 'n' (neuroticism) exists (converted to lowercase 'n')
n_score = user_data['n'].mean() if 'n' in user_data.columns else 0

kpi1.metric("Total Logins", total_logins)
kpi2.metric("After-Hours Access", late_logins, delta_color="inverse")
kpi3.metric("USB Connections", int(usb_count), delta_color="inverse")
kpi4.metric("Neuroticism Score", f"{n_score:.1f}/50")

# 6. VISUALIZATIONS
st.subheader("📈 Risk Timeline")

# Chart: Risk Score Over Time
if 'risk_score' in user_data.columns and 'day' in user_data.columns:
    fig = px.line(user_data, x='day', y='risk_score', 
                  title='Daily Risk Score Progression',
                  markers=True,
                  range_y=[0, 100])
    # Add a red line for the threshold
    fig.add_hline(y=70, line_dash="dash", line_color="red", annotation_text="Critical Threshold")
    fig.add_hline(y=30, line_dash="dash", line_color="orange", annotation_text="Warning Threshold")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Risk Score data not available for plotting.")

# 7. DETAILED LOGS
st.subheader("📋 Detailed Activity Logs")
st.markdown("Transactions flagged as suspicious:")

# Show only rows where risk > 0
if 'risk_score' in user_data.columns:
    suspicious_activity = user_data[user_data['risk_score'] > 25]
    st.dataframe(suspicious_activity.style.background_gradient(subset=['risk_score'], cmap='Reds'))
else:
    st.dataframe(user_data)
