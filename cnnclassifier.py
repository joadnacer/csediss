import pandas as pd
import numpy as np
import time
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import confusion_matrix
from keras import layers
from keras import models
from keras.layers import LSTM
from sklearn.metrics import confusion_matrix
from keras.layers import Embedding
from keras.layers.convolutional import Conv1D
from keras.layers.convolutional import MaxPooling1D
from sklearn.utils import shuffle
df = pd.read_csv("top1mf.csv")
labels = np.asarray(df.label)
df = pd.read_csv("top1mf.csv", usecols=[1])
tokenized = []

for i in range (0, len(df.values)):
	tokenized.append([char for char in df.values[i][0]])

count_vect = CountVectorizer(preprocessor=lambda x:x,
                                 tokenizer=lambda x:x)
X = count_vect.fit_transform(doc for doc in tokenized).todense()
OGX = X
y = labels

for i in range (0, len(y)):
	if y[i] == "benign":
		y[i] = 0
	else:
		y[i] = 1


y_train=np.asarray(y).astype('float32')
validation_split=20000
x_r_validation=X[-39:]
y_r_validation=y_train[-39:]
X = X[:-39]
y_train = y_train[:-39]
X, y_train = shuffle(X, y_train)
x_partial_train=X[validation_split:]
y_partial_train=y_train[validation_split:]
x_b_validation=X[:validation_split]
y_b_validation=y_train[:validation_split]
model=models.Sequential()
model.add(Embedding(100, 32, input_length=51))
model.add(Conv1D(filters=32, kernel_size=3, padding='same', activation='relu'))
model.add(MaxPooling1D(pool_size=2))
model.add(layers.Dropout(0.5))
model.add(LSTM(100))
model.add(layers.Dropout(0.6))
model.add(layers.Dense(1,activation='sigmoid'))
model.compile(optimizer='rmsprop',loss='binary_crossentropy',metrics=['accuracy'])
model.fit(x_partial_train,y_partial_train,epochs=4,batch_size=512,validation_data=(x_r_validation,y_r_validation))

y_pred = (model.predict(x_b_validation).ravel()>0.99)+0 # predict and get class (0 if pred < 0.5 else 1)
cm = confusion_matrix(y_b_validation, y_pred)


target_names = ['benign', 'compromised']

# get predict prob and label 
y_pred = (model.predict(x_partial_train).ravel()>0.6)+0 # predict and get class (0 if pred < 0.6 else 1)
cm = confusion_matrix(y_partial_train, y_pred)
print("===================")
print("train CM:")
print(cm)
print("===================")

y_pred = (model.predict(x_r_validation).ravel()>0.6)+0 # predict and get class (0 if pred < 0.6 else 1)
cm = confusion_matrix(y_r_validation, y_pred)
print("===================")
print("ransomware CM:")
print(cm)
print("===================")

start = time.time_ns()
y_pred = (model.predict(x_b_validation).ravel()>0.6)+0 # predict and get class (0 if pred < 0.6 else 1)
end = time.time_ns()
cm = confusion_matrix(y_b_validation, y_pred)
print("===================")
print("Pred time is " +  str((end-start)/validation_split) + "ns")
print("validation set CM:")
print(cm)

TN = cm[0][0]
FP = cm[0][1]
FN = cm[1][0]
TP = cm [1][1]

print('True Positive(TP)  = ', TP)
print('False Positive(FP) = ', FP)
print('True Negative(TN)  = ', TN)
print('False Negative(FN) = ', FN)
print('')
print('TPR                = ', TP/(TP+FN))
print('FPR                = ', FP/(FP+TN))
print('Precision          = ', TP/(FP+TP))
print("===================")
