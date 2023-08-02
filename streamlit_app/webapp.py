import streamlit as st
import requests
import base64
import pandas as pd


# VirusTotal
# -----------------------------------------------------------------------------------------
def ip_check_virustotal(ip):
    headers = {
        "accept": "application/json",
        "x-apikey": "55322c732c09236145e6515d17ab672e47fe0308a430880b8da237b3e19ed4de"
    }

    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
    response = requests.get(url, headers=headers)

    result_count = {
        "IP Address": ip,
        "Harmless": 0,
        "Undetected": 0,
        "Suspicious": 0,
        "Malicious": 0,
        "Total Sources": 0,
        "Verdict": ""
    }

    if response.status_code == 200:
        data = response.json()

        if "data" in data:
            last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
            for engine, result in last_analysis_results.items():
                category = result["category"]
                if category == "harmless":
                    result_count["Harmless"] += 1
                elif category == "undetected":
                    result_count["Undetected"] += 1
                elif category == "suspicious":
                    result_count["Suspicious"] += 1
                elif category == "malicious":
                    result_count["Malicious"] += 1
                result_count["Total Sources"] += 1

    if result_count["Malicious"] > 5:
        result_count["Verdict"] = "BAD"
    else:
        result_count["Verdict"] = "GOOD"

    return result_count


# IBM X-Force
# -----------------------------------------------------------------------------------------
def send_request(apiurl, scanurl, headers):
    fullurl = apiurl + scanurl
    response = requests.get(fullurl, params='', headers=headers, timeout=20)
    all_json = response.json()
    score = all_json.get('score')
    return score


def ip_check_xforce(ip):
    key = "50a6bc37-39cd-4410-973e-20655115f7d4"
    password = "cd129c71-e97c-4c18-802c-fbc59dd6c31d"

    token = base64.b64encode((key + ":" + password).encode('utf-8'))
    base_headers = {'Authorization': "Basic " +
                    token.decode('utf-8'), 'Accept': 'application/json'}
    url = "https://api.xforce.ibmcloud.com:443"

    apiurl = url + "/ipr/"
    scanurl = ip
    headers = dict(base_headers)
    score = send_request(apiurl, scanurl, headers)

    if score <= 5.0:
        label = "GOOD"
    elif score >= 10.0:
        label = "BAD"
    else:
        label = "BAD"
    return [ip, f"{score}/10.0", label]


# Abuse-IPDB
# -----------------------------------------------------------------------------------------
def ip_check_abuseipdb(ip):
    API = "44300814bf6dcd5d113f86b43a932fd6b883fe7061fe74d1f4b212a37a2d6f964de0d9a8d68bb64d"
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': API
    }

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        decoded_response = response.json()
        if "data" in decoded_response:
            data = decoded_response["data"]
            score = data["abuseConfidenceScore"]
            assessment = ""
            if score >= 0 and score <= 25:
                assessment = "Harmless"
            elif score >= 26 and score <= 75:
                assessment = "Suspicious"
            elif score >= 76 and score <= 100:
                assessment = "Malicious"

            if assessment == "Harmless":
                ab_result = "GOOD"
            else:
                ab_result = "BAD"

            return [data["ipAddress"], score, ab_result]
        else:
            return [ip, "N/A", "N/A"]
    else:
        return [ip, "Error", "N/A"]


# Combined Function
# ----------------------------------------------------------------------------------------
def ip_check_combined(ip):
    vt_result = ip_check_virustotal(ip)
    xf_result = ip_check_xforce(ip)
    ab_result = ip_check_abuseipdb(ip)

    verdict_vt = vt_result['Verdict']
    label_xf = xf_result[2]
    ab_result = ab_result[2]

    verdict_counts = {
        'GOOD': 0,
        'BAD': 0
    }

    if verdict_vt == 'GOOD':
        verdict_counts['GOOD'] += 1
    elif verdict_vt == 'BAD':
        verdict_counts['BAD'] += 1

    if label_xf == 'GOOD':
        verdict_counts['GOOD'] += 1
    elif label_xf == 'BAD':
        verdict_counts['BAD'] += 1

    if ab_result == 'GOOD':
        verdict_counts['GOOD'] += 1
    elif ab_result == 'BAD':
        verdict_counts['BAD'] += 1

    final_verdict = 'GOOD' if verdict_counts['GOOD'] > verdict_counts['BAD'] else 'BAD'

    return final_verdict


def process_ip_addresses(ip_list, choice):
    output_data = []

    if choice == 1:
        for ip in ip_list:
            result = ip_check_virustotal(ip)
            output_data.append(result)

    elif choice == 2:
        key = "50a6bc37-39cd-4410-973e-20655115f7d4"
        password = "cd129c71-e97c-4c18-802c-fbc59dd6c31d"
        token = base64.b64encode((key + ":" + password).encode('utf-8'))
        base_headers = {'Authorization': "Basic " +
                        token.decode('utf-8'), 'Accept': 'application/json'}
        url = "https://api.xforce.ibmcloud.com:443"

        for ip in ip_list:
            apiurl = url + "/ipr/"
            scanurl = ip
            headers = dict(base_headers)
            score = send_request(apiurl, scanurl, headers)

            if score <= 5.0:
                label = "GOOD"
            elif score >= 10.0:
                label = "BAD"
            else:
                label = "BAD"

            result = {
                "IP Address": ip,
                "Score": f"{score}/10.0",
                "Label": label
            }
            output_data.append(result)

    elif choice == 3:
        API = "44300814bf6dcd5d113f86b43a932fd6b883fe7061fe74d1f4b212a37a2d6f964de0d9a8d68bb64d"
        url = 'https://api.abuseipdb.com/api/v2/check'

        for ip in ip_list:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }

            headers = {
                'Accept': 'application/json',
                'Key': API
            }

            response = requests.get(
                url, headers=headers, params=querystring)
            if response.status_code == 200:
                decoded_response = response.json()
                if "data" in decoded_response:
                    data = decoded_response["data"]
                    score = data["abuseConfidenceScore"]
                    assessment = ""
                    if score >= 0 and score <= 25:
                        assessment = "Harmless"
                    elif score >= 26 and score <= 75:
                        assessment = "Suspicious"
                    elif score >= 76 and score <= 100:
                        assessment = "Malicious"

                    if assessment == "Harmless":
                        ab_result = {
                            "IP Address": data["ipAddress"],
                            "abuseConfidenceScore": score,
                            "Final Verdict": "Good"
                        }
                    else:
                        ab_result = {
                            "IP Address": data["ipAddress"],
                            "abuseConfidenceScore": score,
                            "Final Verdict": "Bad"
                        }
                    output_data.append(ab_result)
                else:
                    ab_result = {
                        "IP Address": ip,
                        "abuseConfidenceScore": "N/A",
                        "Final Verdict": "N/A"
                    }
                    output_data.append(ab_result)
            else:
                ab_result = {
                    "IP Address": ip,
                    "abuseConfidenceScore": "Error",
                    "Final Verdict": "N/A"
                }
                output_data.append(ab_result)

    elif choice == 4:
        for ip in ip_list:
            vt_result = ip_check_virustotal(ip)
            xf_result = ip_check_xforce(ip)
            ab_result = ip_check_abuseipdb(ip)

            verdict_vt = vt_result['Verdict']
            label_xf = xf_result[2]
            ab_result = ab_result[2]

            verdict_counts = {
                'GOOD': 0,
                'BAD': 0
            }

            if verdict_vt == 'GOOD':
                verdict_counts['GOOD'] += 1
            elif verdict_vt == 'BAD':
                verdict_counts['BAD'] += 1

            if label_xf == 'GOOD':
                verdict_counts['GOOD'] += 1
            elif label_xf == 'BAD':
                verdict_counts['BAD'] += 1

            if ab_result == 'GOOD':
                verdict_counts['GOOD'] += 1
            elif ab_result == 'BAD':
                verdict_counts['BAD'] += 1

            if verdict_counts['GOOD'] > verdict_counts['BAD']:
                assessment = 'GOOD'
            else:
                assessment = 'BAD'

            if assessment == "GOOD":
                resultant_val = {
                    "IP Address": ip,
                    "Virus Total": verdict_vt,
                    "IBM X-Force": label_xf,
                    "Abuse IPDB": ab_result,
                    "Final Verdict": "Good"
                }
            else:
                resultant_val = {
                    "IP Address": ip,
                    "Virus Total": verdict_vt,
                    "IBM X-Force": label_xf,
                    "Abuse IPDB": ab_result,
                    "Final Verdict": "Bad"
                }
            output_data.append(resultant_val)

    return output_data


def main():
    st.set_page_config(layout="wide")
    hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            </style>
            """
    st.markdown(hide_st_style, unsafe_allow_html=True)
    st.write(
        '<style>div.block-container{padding-top:0rem;}</style>', unsafe_allow_html=True)

    style = "<style>h2 {text-align: center;}</style>"
    st.markdown(style, unsafe_allow_html=True)
    st.columns(3)[1].header("I/P Reputation Checker")

    st.divider()
    st.markdown('#####')
    st.subheader('About the Tool')
    st.markdown(f'''
        ######  
             IP Address Analysis Web App :
               It is a tool that allows users to analyze the reputation and security status of IP 
               addresses using various threat intelligence APIs. This web app simplifies the process of querying multiple APIs 
               and consolidates the results into a single, easy-to-understand output.
        <ul style="padding-left:1px">
        ''', unsafe_allow_html=True)

    st.divider()
    st.markdown('#####')
    st.subheader('Features')
    st.markdown(f'''    
            <ul>
            
             VirusTotal Integration: The web app utilizes the VirusTotal API to retrieve information about the IP addresses, 
                                    including harmless, undetected, suspicious, and malicious classifications from different sources. 
                                    The app then calculates a verdict based on the number of malicious sources.
                                    <a href="https://www.virustotal.com/gui/home/upload"></a>
                                    

           
            IBM X-Force Integration: The IBM X-Force API is utilized to assess the IP addresses' 
                                     reputation score. The reputation score indicates the likelihood of malicious 
                                     activity associated with the IP address. 
                                     The app categorizes the IP address as either "GqqOOD" or "BAD"
                                     based on the score.
            
            Abuse-IPDB Integration: The Abuse-IPDB API is used to check the IP address against its abuse confidence score. 
                                    The score provides insights into the IP address's potential maliciousness. The app determines the 
                                    verdict as "GOOD" or "BAD" based on the score.
                                    Combined Verdict: The app offers the option to obtain a combined verdict by considering the 
                                    verdicts from all three APIs. The final verdict is determined based on a majority decision.
          
        </ul>
        ''', unsafe_allow_html=True)

    st.write("Links to the Individual website : ")
    st.write(
        "[Virustotal](https://www.virustotal.com) , [AbuseIPDB](https://www.abuseipdb.com)")
    st.divider()
    st.markdown('#####')
    st.subheader('Limitations')
    st.markdown(f'''    
            <ul>
            
            API Rate Limits: The web app is subject to rate limits imposed by the APIs it integrates with. 
                             If the rate limits are exceeded, it may impact the responsiveness of the tool or prevent API 
                             calls temporarily.
                             
                             Individual Limits(As mentioned in the documentation of the Website) : 
                                      Virus Total API Rate Limit : 500 requests per day and a rate~ of 4 requests per minute.
                                      Abuse Ipdb Rate Limit : 1,000 IP Checks & Reports / Day
                                      IBM Xforce Rate Limit : Unspecified (Not properly mentioned)
           
            Data Accuracy: The accuracy of the results depends on the accuracy and reliability of the data 
                           provided by the integrated APIs. The web app assumes no responsibility for the accuracy of the results.  
            
            
        </ul>
        ''', unsafe_allow_html=True)

    st.divider()
    st.subheader('Select from the below given options :')
    st.write(" (Note : This webapp will only work if you have input a csv file. To make a csv file for the ip address you need to check just make a simple excel file add all the ip address in the first column and hit save it with any name and extension as .csv and upload the same in the below given box.)")
    menu_choices = {
        1: "Check IP addresses using VirusTotal",
        2: "Check IP addresses using IBM X-Force",
        3: "Check IP addresses using Abuse IPDB",
        4: "Check IP addresses using all three APIs"
    }

    menu_choice = st.radio("", list(menu_choices.values()))
    choice_key = list(menu_choices.keys())[list(
        menu_choices.values()).index(menu_choice)]

    uploaded_file = st.file_uploader(
        "Upload CSV or TXT file", type=["csv", "txt"])

    if uploaded_file is not None:
        try:
            if uploaded_file.type == 'text/csv':
                df = pd.read_csv(uploaded_file)
                ip_addresses = df.iloc[:, 0].tolist()
            else:
                ip_addresses = uploaded_file.read().decode('utf-8').splitlines()

            if st.button("Process IP Addresses"):
                output_data = process_ip_addresses(ip_addresses, choice_key)
                df = pd.DataFrame(output_data)
                st.write("Output:")
                st.write(df)
                st.download_button(
                    "Download CSV",
                    df.to_csv(index=False).encode("utf-8"),
                    "Ip_Analysis.csv",
                    "text/csv",
                    key='download-csv'
                )
        except pd.errors.ParserError:
            st.error('Invalid file format. Please upload a CSV or TXT file.')


if __name__ == "__main__":
    main()
