import vtapi3
import json
from vtapi3 import *
import os

API_KEY = os.environ.get("key")

vt_file = VirusTotalAPIFiles(API_KEY)
vt_url = VirusTotalAPIUrls(API_KEY)
vt_ip = VirusTotalAPIIPAddresses(API_KEY)

# This is to pull up the details on the input hash
def find_hash_details(hash):
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
    print(f"According to VirusTotal the hash value, {hash}({file_name}), was found to be malicious by {malicious}/{total_vendors} security vendors and "
          f"suspicious by {suspicious} additional vendors.  \nAdditionally it has a community score of: {community_score}\n")
    # See if they want additional hash info
    should_continue = True
    while should_continue:
        additional_details = input("Would you like additional details on this hash?(Yes or No)\n")
        if "yes" in additional_details.lower():
            try:
                tags = result["data"]["attributes"]["tags"]
                print("The file was marked with the following tags: " + ', '.join(tags) + "\n")
            except KeyError:
                pass
            # See if the hash is signed
            try:
                signers = result["data"]["attributes"]["signature_info"]["signers"]
                sign_date = result["data"]["attributes"]["signature_info"]["signing date"]
                print(f"The file was signed by as verified {signers} on {sign_date}\n")
            except KeyError:
                pass
            # Looks to see if theres a popular threat label
            try:
                threat = result["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
                print(f"The file has the suggested threat label of {threat}.\n")
            except KeyError:
                pass
            try:
                names = result["data"]["attributes"]["names"]
                names = str(', '.join(names))
                names = names.replace(',', '\n')
                print(f"This file has been reported before under the following names:\n{names}\n")
            except KeyError:
                pass

            print("If you have any suggestions for additional details you'd like to see. Let me know.\n")
            should_continue = False
        elif "no" in additional_details.lower():
            should_continue = False
        else:
            print("I didn't recognize that input.\n")

def find_url_details(url):
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
    print(
        f"According to VirusTotal the url, {url}, was found to be malicious by {malicious}/{total_vendors} security vendors and "
        f"suspicious by {suspicious} additional vendors.  \nAdditionally it has a community score of: {community_score}\n")
    should_continue = True
    while should_continue:
        additional_details = input("Would you like additional details on this url?(Yes or No)\n")
        if "yes" in additional_details.lower():
            try:
                tags = result["data"]["attributes"]["tags"]
                print("The url was marked with the following tags: " + ', '.join(tags) + "\n")
            except KeyError:
                pass
            # See if the it has a threat name
            try:
                threat_name = result["data"]["attributes"]["threat_names"]
                print(f"The url is marked as having the following threat name(s): " + ', '.join(threat_name) + "\n")
            except KeyError:
                pass
            # Looks to see how many people think this is harmless
            try:
                harmless = file_status = result["data"]["attributes"]["last_analysis_stats"]["harmless"]
                print(f"The url was marked as harmless by {harmless} total security vendors.\n")
            except KeyError:
                pass
            try:
                names = result["data"]["attributes"]["names"]
                names = str(', '.join(names))
                names = names.replace(',', '\n')
                print(f"This file has been reported before under the following names:\n{names}\n")
            except KeyError:
                pass

            print("If you have any suggestions for additional details you'd like to see. Let me know.\n")
            should_continue = False
        elif "no" in additional_details.lower():
            should_continue = False
        else:
            print("I didn't recognize that input.\n")


def find_ip_details(ip):
    file = vt_ip.get_report(ip)
    result = json.loads(file)
    print(result)
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
    print(
        f"According to VirusTotal the ip, {ip}, was found to be malicious by {malicious}/{total_vendors} security vendors and "
        f"suspicious by {suspicious} additional vendors.\n"
        f"Additionally it has a community score of: {community_score}\n"
        f"It is owned by the isp {owner} and is located in {country}.")


search_on = True

while search_on:
    search = input("What would you like to search today?(Hash, URL, IP, or Stop)\n")
    if "hash" in search.lower():
        hash = input("Please paste the hash you would like to search:\n")
        find_hash_details(hash)
    elif "url" in search.lower():
        url = input("Please paste the url you would like to search:\n")
        find_url_details(url)
    elif "ip" in search.lower():
        ip = input("Please paste the IP you would like to search:\n")
        find_ip_details(ip)
    elif "stop" in search.lower():
        print("Have a wonderful day, and good threat hunting.")
        search_on = False
    else:
        print("I didn't recognize that input. Please try again. \n")