from tkinter import *
import tkinter as tk
import json
from vtapi3 import *

API_KEY = "f49d021f991ae0f4c0e820dc3181201457ae6949da13b7c460fc8abaa899ee2f"

vt_file = VirusTotalAPIFiles(API_KEY)
vt_url = VirusTotalAPIUrls(API_KEY)
vt_ip = VirusTotalAPIIPAddresses(API_KEY)


window = tk.Tk()
window.title("VirusTotal Searcher")
window.config(background="#ADD8E6")
window.geometry("600x600")


def hash_info():
    details.delete('1.0', END)
    hash = search_bar.get()
    try:
        file = vt_file.get_report(hash)
        result = json.loads(file)
        file_name = result["data"]["attributes"]["meaningful_name"]
        community_score = result["data"]["attributes"]["reputation"]
        file_status = result["data"]["attributes"]["last_analysis_stats"]
        # Removing the search engines that won't search the file and then getting total that searched
        try:
            file_status.pop("type-unsupported")
        except KeyError:
            pass
        value = file_status.values()
        total_vendors = sum(value)
        # display the number who found it malicious
        malicious = file_status["malicious"]
        suspicious = file_status["suspicious"]
        hash_info = (
            f"According to VirusTotal the hash value, {hash}({file_name}), was found to be malicious by {malicious}/{total_vendors} security vendors and "
            f"suspicious by {suspicious} additional vendors.  \nAdditionally it has a community score of: {community_score}\n\n")
        details.insert(INSERT, hash_info)
    except KeyError:
        details.insert(INSERT, "I'm sorry, either VirusTotal didn't find information on that hash or your API key is inaccurate.")
    else:
        try:
            tags = result["data"]["attributes"]["tags"]
            details.insert(INSERT, "The file was marked with the following tags: " + ', '.join(tags) + "\n\n")
        except KeyError:
            pass
        # See if the hash is signed
        try:
            signers = result["data"]["attributes"]["signature_info"]["signers"]
            sign_date = result["data"]["attributes"]["signature_info"]["signing date"]
            details.insert(INSERT, f"The file was signed by as verified {signers} on {sign_date}\n\n")
        except KeyError:
            pass
        # Looks to see if there's a popular threat label
        try:
            threat = result["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
            details.insert(INSERT, f"The file has the suggested threat label of {threat}.\n\n")
        except KeyError:
            pass
        try:
            names = result["data"]["attributes"]["names"]
            names = str(', '.join(names))
            names = names.replace(',', '\n')
            details.insert(INSERT, f"This file has been reported before under the following names:\n{names}\n\n")
        except KeyError:
            pass

def url_info():
    details.delete('1.0', END)
    url = search_bar.get()
    try:
        url_id = vt_url.get_url_id_base64(url)
        file = vt_url.get_report(url_id)
        result = json.loads(file)
        community_score = result["data"]["attributes"]["reputation"]
        file_status = result["data"]["attributes"]["last_analysis_stats"]
        # Removing the search engines that won't search the file and then getting total that searched
        try:
            file_status.pop("type-unsupported")
        except KeyError:
            pass
        value = file_status.values()
        total_vendors = sum(value)
        # display the number who found it malicious
        malicious = file_status["malicious"]
        suspicious = file_status["suspicious"]
        url_details = (
            f"According to VirusTotal the url, {url}, was found to be malicious by {malicious}/{total_vendors} security vendors and "
            f"suspicious by {suspicious} additional vendors.  \nAdditionally it has a community score of: {community_score}\n\n")
        details.insert(INSERT, url_details)
    except KeyError:
        details.insert(INSERT, "I'm sorry, either VirusTotal didn't find information on that URL or your API key is inaccurate.")
    else:
        try:
            tags = result["data"]["attributes"]["tags"]
            details.insert(INSERT, "The url was marked with the following tags: " + ', '.join(tags) + "\n\n")
        except KeyError:
            pass
        # See if the it has a threat name
        try:
            threat_name = result["data"]["attributes"]["threat_names"]
            details.insert(INSERT, f"The url is marked as having the following threat name(s): " + ', '.join(threat_name) + "\n\n")
        except KeyError:
            pass
        # Looks to see how many people think this is harmless
        try:
            harmless = result["data"]["attributes"]["last_analysis_stats"]["harmless"]
            details.insert(INSERT, f"The url was marked as harmless by {harmless} total security vendors.\n\n")
        except KeyError:
            pass
        try:
            names = result["data"]["attributes"]["names"]
            names = str(', '.join(names))
            names = names.replace(',', '\n\n')
            details.insert(INSERT, f"This file has been reported before under the following names:\n{names}\n\n")
        except KeyError:
            pass


def ip_info():
    details.delete('1.0', END)
    ip = search_bar.get()
    try:
        file = vt_ip.get_report(ip)
        result = json.loads(file)
        community_score = result["data"]["attributes"]["reputation"]
        file_status = result["data"]["attributes"]["last_analysis_stats"]
        owner = result["data"]["attributes"]["as_owner"]
        country = result["data"]["attributes"]["country"]
        # Removing the search engines that won't search the file and then getting total that searched
        try:
            file_status.pop("type-unsupported")
        except KeyError:
            pass
        value = file_status.values()
        total_vendors = sum(value)
        # display the number who found it malicious
        malicious = file_status["malicious"]
        suspicious = file_status["suspicious"]
        details.insert(INSERT,
            f"According to VirusTotal the ip, {ip}, was found to be malicious by {malicious}/{total_vendors} security vendors and "
            f"suspicious by {suspicious} additional vendors.\n"
            f"Additionally it has a community score of: {community_score}\n"
            f"It is owned by the isp {owner} and is located in {country}.")
    except KeyError:
        details.insert(INSERT,
                       "I'm sorry, either VirusTotal didn't find information on that IP or your API key is inaccurate.")

def choose_calc():
    choice = clicked.get()
    if choice == "Hash":
        hash_info()
    elif choice == "URL":
        url_info()
    elif choice == "IP Address":
        ip_info()
    else:
        pass


greeting = tk.Label(text="Please tell me what you would like to search:", font=("Arial", 14), background="#ADD8E6")
greeting.place(x=300, y=50, anchor=CENTER)

search_bar = tk.Entry(width=40)
search_bar.place(x=300, y=75, anchor=CENTER)


options = [
    "Hash",
    "IP Address",
    "URL"
]
clicked = StringVar()
clicked.set("Hash")
drop = OptionMenu(window, clicked, *options)
drop.place(x=300, y=110, anchor=CENTER)

enter = tk.Button(window, text="Click Here", command=choose_calc)
enter.place(x=300, y=145, anchor=CENTER)

details = tk.Text(height=25, width=60, wrap=WORD)
details.place(x=300, y=370, anchor=CENTER)


window.mainloop()
