
import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import re
import  tldextract
import mysql.connector as sql
from urllib.parse import urlparse
import urllib.request
import time
import socket
from urllib.error import HTTPError
from datetime import  datetime
import random
from sklearn.metrics import confusion_matrix,accuracy_score




df1=pd.read_csv("C:\\Users\\Riya\\Desktop\\ML\\data\\data.csv")
hostname = "localhost";
username = "root";
password = "";
db_name = "data5";

db_connection = sql.connect(host=hostname, database=db_name, user=username, password=password)
db_cursor = db_connection.cursor()
db_cursor.execute('SELECT * FROM url')

table_rows = db_cursor.fetchall()

fd= pd.read_sql('SELECT * FROM url', con=db_connection)
df= df1.append(fd)
df=df.reset_index(drop=True)

def label(lab):
    if lab == "good":
        return 0
    elif lab == "bad":
        return 1

df["label1"]=[label(ele) if ele else 2 for ele in df["label"]]
df["exist@"]=[1 if "@" in ele else 0 for ele in df["url"]]
df["exist//"]=[1 if ele.find("//")>7 else 0 for ele in df["url"]]
df2=pd.DataFrame()
df2["domain"]=[ tldextract.extract(ele).domain if ele else 0 for ele in df["url"]]
df2['url_len']=df['url'].str.len()
def long_url(ln):
        if ln > 75:
            return 1           # legitimate
        else:
            return 0            # phishing

df["exist_longurl"]=[ long_url(ele) if  ele else 2 for ele in df2["url_len"]]
df["exist_subdomain"]=[1 if len(tldextract.extract(ele).subdomain)>2 else 0 for ele in df["url"]]
def exis(li):
    if "-" in li:
        return 1
    else:
        return 0



df["exist-"]=[exis(ele) if ele else 2 for ele in df2["domain"]]

def is_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except:
        return False

df["ip_exist"]=[1 if is_ip(ele) else 0 for ele in df2["domain"]]
def is_https(urll):
    if "https" in urll[:5]:
        return 0
    else:
        return 1
df["https_exist"]=[ is_https(ele) if ele else 2 for ele in df["url"]]
df2["tld"]=[(tldextract.extract(ele).suffix) if ele else 0 for ele in df["url"]]
df["tld_exist"]=[1 if not ele else 0 for ele in df2["tld"]]
df["exist_"]=[1 if "_" in ele else 0 for ele in df["url"]]
df["exist="]=[1 if "=" in ele else 0 for ele in df["url"]]
def hasnum(uii):
    return any(char.isdigit() for char in uii)
df["exist_digits"]=[1 if  hasnum(ele)  else 0 for ele in df["url"]]
def is_phish(urll):
    list11=['creeksideshowstable.com','altervista.org' ,'sendmaui.net','seriport.com',     
'bjcurio.com','118bm.com ','bjcurio.com','118bm.com ','paypal-system.de','google.com','remorquesfranc.net','178.219.117.72 ','199.204.248.109','79.124.104.31','94.154.60.19','46.174.25.83 ','95.128.74.50','67.208.112.27','91.239.245.32 ','118.244.132.16','159.253.36.2']
    for i in range(len(list11)):
        if list11[i] in urll:
            return 1
        else:
            return 0

df["exist_phisurl"]=[is_phish(ele) if ele  else 2 for ele in df["url"]]
def shortening_service(url):
        """Tiny URL -> phishing otherwise legitimate"""
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate
        
df["exist_tinyurl"]=[shortening_service(ele) if ele  else 2 for ele in df["url"]]
def domain_registration_length(url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1      #phishing
        else:
            expiration_date = domain_name.expiration_date
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            if expiration_date is None:
                return 1
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                    try:
                        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                    except:
                        return 2
                registration_length = abs((expiration_date - today).days)
                if registration_length / 365 <= 1:
                    return 1 #phishing
                else:
                    return 0 # legitimate
df["exist_reglendomain"]=[domain_registration_length(ele) if ele  else 2 for ele in df["url"]]
def age_domain(url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        
        if dns == 1:
            return 1
        else:
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date
            if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                try:
                    creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                except:
                    return 2
            if ((expiration_date is None) or (creation_date is None)):
                return 1
            else:
                ageofdomain = abs((expiration_date - creation_date).days)
                if ((ageofdomain/30) < 12):
                    return 1
                    
                else:
                    return 0					

df["exist_validage"]=[age_domain(ele) if ele  else 2 for ele in df["url"]]
df3=df.copy()
df = df.drop('url',axis=1)
df = df.drop('label',axis=1)
labels = df['label1']
urls_without_labels = df.drop('label1',axis=1)
urls_without_labels.columns
random.seed(100)
data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20, random_state=100)
data_train=data_train.astype(int)
RFmodel = RandomForestClassifier()
RFmodel.fit(data_train,labels_train)
rf_pred_label = RFmodel.predict(data_test)
cm1 = confusion_matrix(labels_test,rf_pred_label)
cas1=accuracy_score(labels_test,rf_pred_label)

lnty=len(df)-1
l15=df['exist@'][lnty]
l1=df['exist//'][lnty]
l2=df['exist_longurl'][lnty]
l3=df['exist_subdomain'][lnty]
l4=df['exist-'][lnty]
l5=df['ip_exist'][lnty]
l6=df['https_exist'][lnty]
l7=df['tld_exist'][lnty]
l8=df['exist_'][lnty]
l9=df['exist='][lnty]
l10=df['exist_digits'][lnty]
l11=df['exist_phisurl'][lnty]
l12=df['exist_tinyurl'][lnty]
l13=df['exist_reglendomain'][lnty]
l14=df['exist_validage'][lnty]

cv1=RFmodel.predict([[l15,l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13,l14]])

from sklearn.tree import DecisionTreeClassifier
DTmodel = DecisionTreeClassifier(criterion = "entropy", random_state = 100,
 max_depth=10, min_samples_leaf=2)
DTmodel.fit(data_train,labels_train)
pred_label = DTmodel.predict(data_test)
cm = confusion_matrix(labels_test,pred_label)
cas2=accuracy_score(labels_test,pred_label)
cv2=DTmodel.predict([[l15,l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13,l14]])

from sklearn.linear_model import LogisticRegression
LogReg = LogisticRegression()
LogReg.fit(data_train,labels_train)
y_pred = LogReg.predict(data_test)
m1 = confusion_matrix(labels_test,y_pred)
cas3=accuracy_score(labels_test,y_pred)
cv3=LogReg.predict([[l15,l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13,l14]])

from sklearn.naive_bayes import MultinomialNB
mnb = MultinomialNB()
mnb.fit(data_train,labels_train)
mnb_pred = mnb.predict(data_test)
m12= confusion_matrix(labels_test,mnb_pred)
cas4=accuracy_score(labels_test,mnb_pred)
cv4=mnb.predict([[l15,l1,l2,l3,l4,l5,l6,l7,l8,l9,l10,l11,l12,l13,l14]])

def compare_accurcy():
    d = {'x':cas1, 'y':cas2, 'z':cas3 , 'w':cas4}
    zw=max(d.items(), key=lambda i: i[1])
    if zw[0]=='x':
        return cv1[0]
    elif zw[0]=='y':
        return cv2[0]
    elif zw[0]=='z':
        return cv3[0]
    else:
        return cv4[0]
cv=compare_accurcy()

def result(cv1):
    if cv1==0:
        print( df3['url'][lnty]+" is a Good Url")
    else:
        print( df3['url'][lnty]+" is a Bad Url")
result(cv)


