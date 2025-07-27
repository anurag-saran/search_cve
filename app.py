import streamlit as st
import asyncio
import httpx
import pandas as pd
from datetime import datetime, timedelta

class RedHatCVEClient:
    def __init__(self):
        self.base_url = "https://access.redhat.com/hydra/rest/securitydata"
        
    async def search_cves(self, product=None, severity=None, limit=50, package=None):
        async with httpx.AsyncClient(timeout=30.0) as client:
            params = {"per_page": min(limit, 1000), "page": 1}
            
            if product:
                params["product"] = product
            if severity:
                params["severity"] = severity.lower()
            if package:
                params["package"] = package
                
            try:
                url = f"{self.base_url}/cve.json"
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                return {
                    "success": True,
                    "cves": data if isinstance(data, list) else [],
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

def format_cve_data(cves):
    """Convert CVE data to a pandas DataFrame for display"""
    formatted_data = []
    
    for cve in cves:
        if not isinstance(cve, dict):
            continue
            
        # Extract relevant information
        cve_id = cve.get("CVE", "Unknown")
        severity = cve.get("severity", cve.get("ThreatSeverity", "Unknown"))
        public_date = cve.get("public_date", cve.get("PublicDate", "Unknown"))
        
        # Get description
        description = "No description"
        if "bugzilla" in cve and isinstance(cve["bugzilla"], dict):
            description = cve["bugzilla"].get("description", "No description")
        elif "Bugzilla" in cve and isinstance(cve["Bugzilla"], dict):
            description = cve["Bugzilla"].get("description", "No description")
        
        # Get CVSS score
        cvss_score = "N/A"
        if "cvss3" in cve and isinstance(cve["cvss3"], dict):
            cvss_score = cve["cvss3"].get("cvss3_base_score", "N/A")
        elif "CVSS3" in cve and isinstance(cve["CVSS3"], dict):
            cvss_score = cve["CVSS3"].get("cvss3_base_score", "N/A")
        
        formatted_data.append({
            "CVE ID": cve_id,
            "Severity": severity,
            "CVSS Score": cvss_score,
            "Public Date": public_date,
            "Description": description[:100] + "..." if len(str(description)) > 100 else description
        })
    
    return pd.DataFrame(formatted_data)

def main():
    st.set_page_config(page_title="Red Hat CVE Search Tool", page_icon="🔍", layout="wide")
    
    st.title("🔍 Red Hat CVE Search Tool")
    st.markdown("Search for Common Vulnerabilities and Exposures (CVEs) in Red Hat products")
    
    # Sidebar for search parameters
    st.sidebar.header("Search Parameters")
    
    # Product selection
    common_products = [
        "",  # Empty option
        "Red Hat Enterprise Linux",
        "Red Hat Enterprise Linux 9",
        "Red Hat Enterprise Linux 8", 
        "Red Hat Enterprise Linux 7",
        "Red Hat OpenShift Container Platform",
        "Red Hat OpenStack Platform",
        "Red Hat Satellite",
        "Red Hat JBoss Enterprise Application Platform",
    ]
    
    product = st.sidebar.selectbox("Select Product:", common_products)
    custom_product = st.sidebar.text_input("Or enter custom product:")
    final_product = custom_product if custom_product else product
    
    # Package search
    package = st.sidebar.text_input("Package name (e.g., kernel, openssl):")
    
    # Severity filter
    severity = st.sidebar.selectbox("Severity:", ["", "Critical", "Important", "Moderate", "Low"])
    
    # Result limit
    limit = st.sidebar.slider("Max results:", min_value=1, max_value=100, value=20)
    
    # Search button
    if st.sidebar.button("🔍 Search CVEs"):
        if not final_product and not package:
            st.error("Please specify either a product or package name")
            return
        
        with st.spinner("Searching for CVEs..."):
            client = RedHatCVEClient()
            
            # Run async function
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    client.search_cves(
                        product=final_product,
                        package=package,
                        severity=severity,
                        limit=limit
                    )
                )
                loop.close()
                
                if result["success"]:
                    cves = result["cves"]
                    
                    if not cves:
                        st.warning("No CVEs found with the specified criteria")
                        return
                    
                    st.success(f"Found {len(cves)} CVEs")
                    
                    # Display results in a table
                    df = format_cve_data(cves)
                    st.dataframe(df, use_container_width=True)
                    
                    # Detailed view
                    st.subheader("Detailed View")
                    for i, cve in enumerate(cves[:10]):  # Show first 10 in detail
                        if not isinstance(cve, dict):
                            continue
                            
                        with st.expander(f"{cve.get('CVE', 'Unknown')} - {cve.get('severity', 'Unknown')}"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write(f"**CVE ID:** {cve.get('CVE', 'Unknown')}")
                                st.write(f"**Severity:** {cve.get('severity', 'Unknown')}")
                                st.write(f"**Public Date:** {cve.get('public_date', 'Unknown')}")
                                
                                if "cvss3" in cve and isinstance(cve["cvss3"], dict):
                                    st.write(f"**CVSS3 Score:** {cve['cvss3'].get('cvss3_base_score', 'N/A')}")
                            
                            with col2:
                                if "bugzilla" in cve and isinstance(cve["bugzilla"], dict):
                                    st.write(f"**Bugzilla ID:** {cve['bugzilla'].get('id', 'N/A')}")
                                    description = cve['bugzilla'].get('description', 'No description')
                                    st.write(f"**Description:** {description}")
                
                else:
                    st.error(f"Error searching CVEs: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
    
    # Information section
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This tool searches the Red Hat Security Data API for CVE information. You can:
    - Search by Red Hat product name
    - Filter by package name (like 'kernel', 'openssl')
    - Filter by severity level
    - View detailed CVE information including CVSS scores and descriptions
    
    Data is sourced directly from Red Hat's official Security Data API.
    """)

if __name__ == "__main__":
    main()
