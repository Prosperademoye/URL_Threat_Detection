import os
import pandas as pd
from urllib.parse import urlparse
import re
import requests
import whois
from datetime import datetime

def load_url_dataset(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError("File not found")
    if file_path.endswith(".csv"):
        print('csv seen')
        data = pd.read_csv(file_path)
        return data

def extract_url_features(url):
    features = {}
    try:
        # Parse the URL https://www.youtube.com/watch?v=ZGMIYNdXZIw
        parsed_url = urlparse(url)
        
        # Structural Features
        features['url_length'] = len(url) #we check the url length
        features['domain_length'] = len(parsed_url.netloc) #we check the url domain length "www.youtube.com". 
        #we use netloc to pick the domain out. and then we can do whatever we want.
        features['path_length'] = len(parsed_url.path)# check the path length "watch"
        
        features['num_subdomains'] = len(parsed_url.netloc.split('.')) - 2 #check the number of subdomain "www"
        features['num_special_chars'] = len(re.findall(r'[@#%&?]', url)) #checlk if it has any special characters
        features['has_ip_address'] = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc)) #check if it has an ip address
        features['uses_https'] = url.startswith('https://') #check if it uses https
        
        # Content Features
        features['suspicious_keywords'] = any(keyword in url.lower() for keyword in ['login', 'update', 'secure', 'bank']) #check if it is any of these keywords are in the url
        features['num_digits_in_domain'] = len(re.findall(r'\d', parsed_url.netloc)) #count all the numbers in the domain
        features['letter_to_digit_ratio'] = (sum(c.isalpha() for c in parsed_url.netloc) / 
                                             max(sum(c.isdigit() for c in parsed_url.netloc), 1))

        # Host-Based Features
        try:
            domain_info = whois.whois(parsed_url.netloc) #grab all the information on the domain using whois
            # whois is a library used to get all the informatoin about a domain. it returns bare informations.
            features['domain_age_days'] = (datetime.now() - domain_info.creation_date[0]).days if domain_info.creation_date else 0 #get how old the domain is. if it doesn't have one, return 0
            features['domain_registration_length'] = (domain_info.expiration_date[0] - domain_info.creation_date[0]).days if domain_info.expiration_date and domain_info.creation_date else 0 #how long the domain is available for
        except Exception:
            features['domain_age_days'] = -1 #if there's no domain days return -1
            features['domain_registration_length'] = -1 #if there's no registration length return -1

        # Behavioral Features
        try:
            response = requests.head(url, allow_redirects=True, timeout=5) 
            features['num_redirects'] = len(response.history) #We can check how many redirects we get from the url
        except Exception:
            features['num_redirects'] = -1

        # Statistical Features
        features['longest_token_length'] = max(len(token) for token in re.split(r'[./-]', url))
        features['num_unique_chars'] = len(set(url))

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return None

    print(features)
    return features
    
def batch_extract_features(csv_file, output_file):
    data = pd.read_csv(csv_file) #read the csv 
    
    if 'url' not in data.columns or 'label' not in data.columns: #throw an error if there's not columns called "url" or "data"
        raise ValueError("Must contain url and lebl columns")
    
    extracted_data = [] #store all our extracted data
    
    for index, row in data.iterrows: #iterate through all the rows
        url = row["url"]
        label = row["label"]
        
        features = extract_url_features(url) #run function extract all features using the url the loop is currenttly on
        if features: # if the feature is not null
            features['label'] = label #get the feature and its corresponding label together like a dic
        
        extracted_data.append(features) #append into the extracted_data array
        
    features_df = pd.DataFrame(extracted_data) #convert the whole feartures into a dataframe so the model can be able to use ut properly
    
    features_df.to_csv(output_file, index=False) #put the dataframe in a csv
    print("saved to csv")


    
    





if __name__ == "__main__":
    urls = "malicious_phis.csv"
    batch_extract_features(urls)