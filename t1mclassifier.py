import pandas as pd
import numpy as np
import time
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import shuffle

df = pd.read_csv("top1mf.csv")
labels = np.asarray(df.label)
df = pd.read_csv("top1mf.csv", usecols=[1])
tokenized = []

for i in range (0, len(df.values)):
	tokenized.append([char for char in df.values[i][0]])
	
count_vect = CountVectorizer(preprocessor=lambda x:x,
                                 tokenizer=lambda x:x)
X = count_vect.fit_transform(doc for doc in tokenized)

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


#lr=LogisticRegression(max_iter=1000)
#lr=RandomForestClassifier(verbose=3,n_jobs=-1)
lr=SVC(probability=True, verbose=True)
lr.fit(x_partial_train, y_partial_train)
print("score on train: "+ str(lr.score(x_partial_train, y_partial_train)))

start = time.time_ns()
predictions =  (lr.predict_proba(x_b_validation)[:,1] >= 0.7).astype(bool)
end = time.time_ns()
print("Pred time is " +  str((end-start)/validation_split) + "ns")

#predictions = (model.predict_proba(X)[:,1] >= 0.9).astype(bool)
cm = confusion_matrix(y_b_validation, predictions)

TN, FP, FN, TP = confusion_matrix(y_b_validation, predictions).ravel()

print('True Positive(TP)  = ', TP)
print('False Positive(FP) = ', FP)
print('True Negative(TN)  = ', TN)
print('False Negative(FN) = ', FN)
print('')
print('TPR                = ', TP/(TP+FN))
print('FPR                = ', FP/(FP+TN))
print('Precision          = ', TP/(FP+TP))

#pred = lr.predict_proba(X)
#for i in range (0,len(pred)):
	#print(str(pred[i]) + " " + df.values[i])


predictions = lr.predict_proba(x_r_validation)
count = 0


for pred in predictions[-39:]:
	if (pred[1] > 0.7):
		count += 1



print(str(count) + " urls identified as malicious out of 39")



