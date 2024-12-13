import os
import pandas as pd
from urllib.parse import urlparse
import re
import requests
import whois
from datetime import datetime
from functools import lru_cache
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
import joblib

def load_url_dataset(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError("File not found")
    if file_path.endswith(".csv"):
        # print('csv seen')
        data = pd.read_csv(file_path)
        return data

@lru_cache(maxsize=1000)
def cached_whois(domain):
    try: 
        return whois.whois(domain)
    except Exception:
        return None
    
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
            domain_info = cached_whois(parsed_url.netloc) #grab all the information on the domain using whois
            # whois is a library used to get all the informatoin about a domain. it returns bare informations.
            if domain_info:
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

    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return None
    return features
    
def batch_extract_features(csv_file, output_file):
    data = pd.read_csv(csv_file) #read the csv 
    
    if 'url' not in data.columns or 'label' not in data.columns: #throw an error if there's not columns called "url" or "data"
        raise ValueError("Must contain url and lebl columns")
    
    extracted_data = [] #store all our extracted data
    
    for index, row in data.iterrows(): #iterate through all the rows
        url = row["url"]
        label = row["label"]
        
        features = extract_url_features(url) #run function extract all features using the url the loop is currenttly on
        if features: # if the feature is not null
            features['label'] = label #get the feature and its corresponding label together like a dic
          
        print(f"Processed URL {index + 1}/{len(data)}:")
        print(f"URL:{url}")
        print(f"Extracted Features: {features}\n")
        
        extracted_data.append(features) #append into the extracted_data array
        
    features_df = pd.DataFrame(extracted_data) #convert the whole feartures into a dataframe so the model can be able to use ut properly
    
    features_df.to_csv(output_file, index=False) #put the dataframe in a csv
    print("saved to csv")


    
def preprocess_and_EDA(data):
    print(data.isnull().sum())
    data['domain_age_days'] = data['domain_age_days'].fillna(-1)
    data['domain_registration_length'] = data['domain_registration_length'].fillna(-1)
    print(data.isnull().sum())
    print(data['label'].value_counts())
    
    #scale some features
    to_scale = ['url_length', 'domain_length', 'path_length', 'num_subdomains', 
            'num_special_chars', 'num_digits_in_domain', 'letter_to_digit_ratio', 
            'domain_age_days', 'domain_registration_length', 'num_redirects']
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(data[to_scale])
    scaled_data = pd.DataFrame(scaled_features,columns=to_scale)
    data[to_scale] = scaled_data
    
    # Convert boolean columns to integers
    data['suspicious_keywords'] = data['suspicious_keywords'].astype(int)
    data['uses_https'] = data['uses_https'].astype(int)
    data['has_ip_address'] = data['has_ip_address'].astype(int)
    
    # Initialize LabelEncoder
    label_encoder = LabelEncoder()
    # Encode the labels
    data['label'] = label_encoder.fit_transform(data['label'])
    
    prepocess_df = pd.DataFrame(data)
    prepocess_df.to_csv('preprocess.csv', index=False)
    
    

def model_training(data):
    X = data.drop(columns=['label'])
    y = data['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = XGBClassifier(objective='multi:softmax', num_class=3)
    scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')  
    print(f"Cross-validation scores: {scores}")
    print(f"Mean accuracy: {scores.mean()}")
    model = model.fit(X_train,y_train)
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test set accuracy: {accuracy}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    return model
    
def save_model(model,model_path):
    joblib.dump(model,model_path)
    print("MOdel_saved")
    
def load_trained_model(file_path):
    model = joblib.load(file_path)
    print(f"Model loaded from {file_path}")
    return model

if __name__ == "__main__":
    # urls = "malicious_phish_all.csv"
    urls = "output2.csv"
    output = "output.csv"
    model_path = "model.joblib"
    # batch_extract_features(urls, output)
    # dataset = load_url_dataset("output.csv")
    # preprocess_and_EDA(dataset)
    
    preprocessed_dataset = load_url_dataset("preprocess.csv")
    model = model_training(preprocessed_dataset)
    
    save_model(model,model_path)
    load_trained_model(model_path)
    
    
    
    
    
    