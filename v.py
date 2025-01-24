import streamlit as st
import requests
import time  # To add delays while waiting for the report

# Streamlit App Title
st.title("VirusTotal File Scanner")
hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            </style>
            """
# VirusTotal API URLs
upload_url = "https://www.virustotal.com/api/v3/files"
report_url = "https://www.virustotal.com/api/v3/analyses/{}"

# Your VirusTotal API Key
API_KEY = "8f64bc618624293f1c835145a15979731e96c86b10bfad8fdc021d05877dc4b8"

# File Upload Section
uploaded_file = st.file_uploader("Upload a file to scan", type=["exe", "pdf", "txt", "doc", "jpg", "png", "zip"])

if uploaded_file:
    st.write("File uploaded successfully. Sending to VirusTotal for scanning...")
    
    # VirusTotal Headers
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY  # API key added here
    }

    # Prepare the File for the API
    files = {
        "file": (uploaded_file.name, uploaded_file, "multipart/form-data")
    }

    # Step 1: Upload File and Get Analysis ID
    try:
        response = requests.post(upload_url, headers=headers, files=files)
        
        if response.status_code == 200:
            analysis_id = response.json()["data"]["id"]
            st.success(f"File uploaded successfully! Analysis ID: {analysis_id}")
            
            # Step 2: Retrieve the Report
            st.write("Waiting for the report...")
            time.sleep(15)  # Add a delay to ensure the scan is complete
            
            # Fetch the scan report
            report_response = requests.get(report_url.format(analysis_id), headers=headers)
            
            if report_response.status_code == 200:
                report = report_response.json()
                
                # Display the Report Summary
                stats = report["data"]["attributes"]["stats"]
                harmless = stats["harmless"]
                malicious = stats["malicious"]
                suspicious = stats["suspicious"]
                undetected = stats["undetected"]

                st.write("### Scan Results:")
                st.write(f"- **Harmless detections**: {harmless}")
                st.write(f"- **Malicious detections**: {malicious}")
                st.write(f"- **Suspicious detections**: {suspicious}")
                st.write(f"- **Undetected**: {undetected}")
                
                # Show overall result
                if malicious > 0:
                    st.error("The file is malicious!")
                elif suspicious > 0:
                    st.warning("The file is suspicious.")
                else:
                    st.success("The file is safe.")
            else:
                st.error("Failed to fetch the scan report.")
                st.write(report_response.text)
        else:
            st.error(f"Error: {response.status_code}")
            st.write(response.text)

    except Exception as e:
        st.error("An error occurred while connecting to the VirusTotal API.")
        st.write(e)
