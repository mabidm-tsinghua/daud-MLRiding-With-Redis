
import redis
import json

import logging.config

logger = logging.getLogger(__name__)

from datetime import datetime
import time
from typing import Dict
import json
import re
import pickle
import numpy as np
import pandas as pd

from machinelearning import ClassDetail

def getAlertLevel(probability, predicted_class):
    if(probability <= 50 or predicted_class == 'normal'):
        return 'Level 0'
    elif (probability > 50 and probability <= 60):
        return 'Level 1'
    elif (probability > 60 and probability <= 70):
        return 'Level 2'
    elif (probability > 70 and probability < 80):
        return 'Level 3'
    elif (probability >= 80 and probability <= 100):
        return 'Level 4'

def predict():

    alert = {}
    head = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Fwd Bytes/Bulk Avg', 'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg', 'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg', 'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']
    try:
        f = open('alerts/alerts.json', 'w')
        f.close()

        r = redis.StrictRedis(host='localhost', port=6379, db=0)

        # construct pubsub interface and subscribe to a channel
        p = r.pubsub()
        p.subscribe('my_channel')

        while True:
            message = p.get_message()
            if message and not(isinstance(message['data'], int)):
                refine = []
                each = json.loads(message['data'])
                refine.append(each)
                current_batch_id = str(time.time()).replace('.','')
                
                df = pd.DataFrame(refine, columns=head)
                rows, cols = df.shape
                if rows == 0:
                    print('rows are zero')
                    continue
                
                if rows == 0:
                    print("this line should not be runing")
                    
                orginal_flow = df.copy()
                ndataset=df.drop(['Src IP','Src Port','Dst IP','Dst Port','Protocol','Timestamp'], axis=1)
                # Removing whitespaces in column names.
                ncol_names = [col.replace(' ', '') for col in ndataset.columns]
                ndataset.columns = ncol_names
                nlabel_names = ndataset['Label'].unique()
                nlabel_names = [re.sub("[^a-zA-Z ]+", "", l) for l in nlabel_names]
                nlabel_names = [re.sub("[\s\s]", '_', l) for l in nlabel_names]
                nlabel_names = [lab.replace("__", "_") for lab in nlabel_names]
                nlabel_names, len(nlabel_names)	
                ndataset.dropna(inplace=True)
                # ## Removing *non-finite* values
                ndataset = ndataset.loc[:, ndataset.columns != 'Label'].astype('float64')
                # Replacing infinite values with NaN values.
                ndataset = ndataset.replace([np.inf, -np.inf], np.nan)
                # Removing new NaN values.
                ndataset.dropna(inplace=True)
                novar = "models/novariance_stack_ensemble_model_9807.sav"
                features_no_variance = pickle.load(open(novar, 'rb'))
                ndataset = ndataset.drop(columns=features_no_variance)
                nfeatures = ndataset.loc[:, ndataset.columns != 'Label'].astype('float64')
                sclr= "models/scaler_stack_ensemble_model_9807.sav"	
                scaler = pickle.load(open(sclr,'rb'))
                nfeatures=scaler.transform(nfeatures)
                modl= "models/stack_ensemble_model_9807.sav"
                model= pickle.load((open(modl,'rb')))
                npreds_classes = model.predict(nfeatures)
                x= npreds_classes.shape[0]
                labl = "models/LE_stack_ensemble_model_9807.sav"
                LE= pickle.load((open(labl,'rb')))
                names=LE.inverse_transform([0,1,2,3,4,5,6,7,8,9,10,11,12])
                # printing the tuples in object directly
                high=0
                L=[]
                for name in enumerate(names):
                    y=0
                    for i in npreds_classes:
                        if i==name[0]:
                            y=y+1
                    L.append(((y*100)/(x)))
                    if (y*100)/(x) >= high:
                        high= (y*100)/(x)
                        predicted_class= name[1]
                    if name[1]=='XssWeb' or name[1] =='normal':
                        # print(name[1]+":\t\t"+str(((y*100)/x))[:6])
                        alert[name[1]] = str(((y*100)/x))[:6]
                    else:
                        # print(name[1]+":\t"+str(((y*100)/x))[:6])
                        alert[name[1]] = str(((y*100)/x))[:6]

                alert['flow_id'] = current_batch_id
                alert['description'] = ClassDetail.CLASS_DETAIL[predicted_class]
                alert['predicted_class'] = predicted_class
                alert['predicted_class_probability'] = str(high)
                alert['level'] = getAlertLevel(high, predicted_class)
                alert['flow'] = orginal_flow.to_dict('records')[0]
                now = datetime.now()
                # alert['timestamp'] = now.strftime("%d/%m/%Y %H:%M:%S")
                # print("alert is going to be saved")
                # print(json.dumps(alert))
                with open('alerts/alerts.json', 'a+') as alerts:
                    alerts.write(json.dumps(alert)+'\n')

    except Exception as e:
        logger.info("Error while calling sniffer.")
        logger.exception(e)


        