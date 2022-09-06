import pandas as pd
import numpy as np
import time
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import confusion_matrix
from keras import layers
from keras import models
from keras import regularizers
from sklearn.metrics import confusion_matrix
import tensorflow as tf
import scipy as sp
from sklearn.utils import shuffle

vocabchars = [char for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"]

df = pd.read_csv("top1mf.csv")
labels = np.asarray(df.label)
df = pd.read_csv("top1mf.csv", usecols=[1])
tokenized = []

for i in range (0, len(df.values)):
	tokenized.append([char for char in df.values[i][0]])

count_vect = CountVectorizer(preprocessor=lambda x:x,
                                 tokenizer=lambda x:x, vocabulary=vocabchars)
X = count_vect.fit_transform(doc for doc in tokenized)
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
model.add(layers.Dense(100,kernel_regularizer=regularizers.l2(0.003),activation='relu',input_shape=(66,)))
model.add(layers.Dropout(0.5))
model.add(layers.Dense(100,kernel_regularizer=regularizers.l2(0.003),activation='relu'))
model.add(layers.Dropout(0.6))
model.add(layers.Dense(1,activation='sigmoid'))
model.compile(optimizer='rmsprop',loss='binary_crossentropy',metrics=['accuracy'])

sp.sparse.csr_matrix.sort_indices(x_partial_train)
sp.sparse.csr_matrix.sort_indices(x_r_validation)
sp.sparse.csr_matrix.sort_indices(x_b_validation)

model.fit(x_partial_train,y_partial_train,epochs=4,batch_size=512,validation_data=(x_r_validation,y_r_validation))

print("score on ransomware test: " + str(model.evaluate(x_r_validation,y_r_validation)[1]))
print("score on benign test: " + str(model.evaluate(x_b_validation,y_b_validation)[1]))
print("score on train: "+ str(model.evaluate(x_partial_train,y_partial_train)[1]))

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
print("ransomware CM and probas:")
print(cm)
print(model.predict(x_r_validation))
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

model.save("domain_classifier")
