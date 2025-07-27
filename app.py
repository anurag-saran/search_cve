import streamlit as st
import asyncio
import httpx
import pandas as pd
from datetime import datetime, timedelta
import json

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

def analyze_cve_data(cves, question):
    """Analyze CVE data based on user question"""
    if not cves:
        return "No CVE data available to analyze."
    
    # Convert to DataFrame for easier analysis
    df = format_cve_data(cves)
    
    question_lower = question.lower()
    
    # Different types of analysis based on question keywords
    if any(word in question_lower for word in ['how many', 'count', 'number']):
        total = len(df)
        severity_counts = df['Severity'].value_counts()
        analysis = f"**Total CVEs found: {total}**\n\n"
        analysis += "**Breakdown by severity:**\n"
        for severity, count in severity_counts.items():
            analysis += f"- {severity}: {count}\n"
        return analysis
    
    elif any(word in question_lower for word in ['critical', 'severe', 'high risk']):
        critical_cves = df[df['Severity'].str.lower().isin(['critical', 'important'])]
        if critical_cves.empty:
            return "No critical or important CVEs found in the current results."
        
        analysis = f"**Found {len(critical_cves)} critical/important CVEs:**\n\n"
        for _, cve in critical_cves.head(10).iterrows():
            analysis += f"- **{cve['CVE ID']}** ({cve['Severity']}) - CVSS: {cve['CVSS Score']}\n"
            analysis += f"  {cve['Description'][:150]}...\n\n"
        return analysis
    
    elif any(word in question_lower for word in ['recent', 'latest', 'new']):
        # Sort by date if possible
        recent_analysis = f"**Most recent CVEs from the search:**\n\n"
        for _, cve in df.head(10).iterrows():
            recent_analysis += f"- **{cve['CVE ID']}** ({cve['Severity']}) - {cve['Public Date']}\n"
            recent_analysis += f"  {cve['Description'][:100]}...\n\n"
        return recent_analysis
    
    elif any(word in question_lower for word in ['summary', 'overview', 'summarize']):
        total = len(df)
        severity_counts = df['Severity'].value_counts()
        
        # Calculate risk level
        high_risk = severity_counts.get('Critical', 0) + severity_counts.get('Important', 0)
        risk_percentage = (high_risk / total * 100) if total > 0 else 0
        
        analysis = f"**CVE Summary Report**\n\n"
        analysis += f"- **Total vulnerabilities:** {total}\n"
        analysis += f"- **High risk (Critical/Important):** {high_risk} ({risk_percentage:.1f}%)\n"
        analysis += f"- **Risk assessment:** {'HIGH RISK' if risk_percentage > 30 else 'MODERATE RISK' if risk_percentage > 10 else 'LOW RISK'}\n\n"
        
        analysis += "**Severity breakdown:**\n"
        for severity, count in severity_counts.items():
            percentage = (count / total * 100) if total > 0 else 0
            analysis += f"- {severity}: {count} ({percentage:.1f}%)\n"
        
        # Show top CVEs
        analysis += f"\n**Top 5 CVEs by severity:**\n"
        priority_order = {'Critical': 4, 'Important': 3, 'Moderate': 2, 'Low': 1}
        df['Priority'] = df['Severity'].map(priority_order).fillna(0)
        top_cves = df.nlargest(5, 'Priority')
        
        for _, cve in top_cves.iterrows():
            analysis += f"- **{cve['CVE ID']}** ({cve['Severity']}) - CVSS: {cve['CVSS Score']}\n"
        
        return analysis
    
    elif any(word in question_lower for word in ['recommendation', 'what should', 'action', 'priority']):
        critical_count = len(df[df['Severity'].str.lower() == 'critical'])
        important_count = len(df[df['Severity'].str.lower() == 'important'])
        
        recommendations = "**Security Recommendations:**\n\n"
        
        if critical_count > 0:
            recommendations += f"🚨 **URGENT**: {critical_count} Critical vulnerabilities found!\n"
            recommendations += "- Patch immediately, ideally within 24-48 hours\n"
            recommendations += "- Consider emergency maintenance windows\n"
            recommendations += "- Implement additional monitoring\n\n"
        
        if important_count > 0:
            recommendations += f"⚠️ **HIGH PRIORITY**: {important_count} Important vulnerabilities found!\n"
            recommendations += "- Schedule patching within 1-2 weeks\n"
            recommendations += "- Review affected systems\n"
            recommendations += "- Plan maintenance windows\n\n"
        
        recommendations += "**General Actions:**\n"
        recommendations += "- Review all affected packages and systems\n"
        recommendations += "- Test patches in non-production environment first\n"
        recommendations += "- Document patching activities\n"
        recommendations += "- Monitor systems post-patching\n"
        
        return recommendations
    
    else:
        # Generic analysis
        return f"I found {len(df)} CVEs. Here are some key insights:\n\n" + \
               f"**Severity distribution:**\n{df['Severity'].value_counts().to_string()}\n\n" + \
               "You can ask me specific questions like:\n" + \
               "- 'How many critical CVEs are there?'\n" + \
               "- 'Summarize the security risk'\n" + \
               "- 'What are your recommendations?'\n" + \
               "- 'Show me the most recent vulnerabilities'"

def main():
    st.set_page_config(page_title="Red Hat CVE Search & Chat Tool", page_icon="🔍", layout="wide")
    
    st.title("🔍 Red Hat CVE Search & Chat Tool")
    st.markdown("Search for CVEs and chat about the security data")
    
    # Initialize session state for chat and CVE data
    if "cve_data" not in st.session_state:
        st.session_state.cve_data = []
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "search_performed" not in st.session_state:
        st.session_state.search_performed = False
    
    # Create two columns - Search on left, Chat on right
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.header("🔍 CVE Search")
        
        # Search parameters
        with st.form("cve_search_form"):
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
            
            product = st.selectbox("Select Product:", common_products)
            custom_product = st.text_input("Or enter custom product:")
            final_product = custom_product if custom_product else product
            
            # Package search
            package = st.text_input("Package name (e.g., kernel, openssl):")
            
            # Severity filter
            severity = st.selectbox("Severity:", ["", "Critical", "Important", "Moderate", "Low"])
            
            # Result limit
            limit = st.slider("Max results:", min_value=1, max_value=100, value=20)
            
            # Search button
            search_submitted = st.form_submit_button("🔍 Search CVEs")
        
        if search_submitted:
            if not final_product and not package:
                st.error("Please specify either a product or package name")
            else:
                with st.spinner("Searching for CVEs..."):
                    client = RedHatCVEClient()
                    
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
                            st.session_state.cve_data = result["cves"]
                            st.session_state.search_performed = True
                            st.success(f"Found {len(result['cves'])} CVEs")
                            
                            if result["cves"]:
                                # Display results in a table
                                df = format_cve_data(result["cves"])
                                st.dataframe(df, use_container_width=True)
                            else:
                                st.warning("No CVEs found with the specified criteria")
                        else:
                            st.error(f"Error searching CVEs: {result.get('error', 'Unknown error')}")
                            
                    except Exception as e:
                        st.error(f"An error occurred: {str(e)}")
    
    with col2:
        st.header("💬 Chat About CVEs")
        
        if not st.session_state.search_performed:
            st.info("👈 First, search for CVEs using the form on the left, then you can ask questions about the results here!")
        else:
            st.success(f"Loaded {len(st.session_state.cve_data)} CVEs. Ask me anything about them!")
            
            # Chat interface
            chat_container = st.container()
            
            # Display chat history
            with chat_container:
                for i, (question, answer) in enumerate(st.session_state.chat_history):
                    with st.chat_message("user"):
                        st.write(question)
                    with st.chat_message("assistant"):
                        st.write(answer)
            
            # Chat input
            user_question = st.chat_input("Ask about the CVE data...")
            
            if user_question:
                # Add user question to chat history
                with st.chat_message("user"):
                    st.write(user_question)
                
                # Generate analysis
                with st.chat_message("assistant"):
                    with st.spinner("Analyzing CVE data..."):
                        analysis = analyze_cve_data(st.session_state.cve_data, user_question)
                        st.write(analysis)
                
                # Add to chat history
                st.session_state.chat_history.append((user_question, analysis))
            
            # Quick action buttons
            st.markdown("**Quick Questions:**")
            col_a, col_b = st.columns(2)
            
            with col_a:
                if st.button("📊 Summarize risks"):
                    analysis = analyze_cve_data(st.session_state.cve_data, "summarize the security risks")
                    st.session_state.chat_history.append(("Summarize the security risks", analysis))
                    st.rerun()
                
                if st.button("🚨 Show critical CVEs"):
                    analysis = analyze_cve_data(st.session_state.cve_data, "show critical vulnerabilities")
                    st.session_state.chat_history.append(("Show critical vulnerabilities", analysis))
                    st.rerun()
            
            with col_b:
                if st.button("💡 Get recommendations"):
                    analysis = analyze_cve_data(st.session_state.cve_data, "what are your recommendations")
                    st.session_state.chat_history.append(("What are your recommendations?", analysis))
                    st.rerun()
                
                if st.button("📈 Count by severity"):
                    analysis = analyze_cve_data(st.session_state.cve_data, "how many CVEs by severity")
                    st.session_state.chat_history.append(("How many CVEs by severity?", analysis))
                    st.rerun()
            
            # Clear chat button
            if st.button("🗑️ Clear chat"):
                st.session_state.chat_history = []
                st.rerun()
    
    # Information section
    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
    This enhanced tool lets you:
    - 🔍 Search Red Hat CVE data by product, package, or severity
    - 💬 Chat and ask questions about the vulnerability data
    - 📊 Get automated analysis and security recommendations
    - 🚨 Quickly identify critical security issues
    
    **Example questions you can ask:**
    - "How many critical CVEs are there?"
    - "Summarize the security risks"
    - "What should I prioritize?"
    - "Which CVEs affect the kernel?"
    """)

if __name__ == "__main__":
    main()
