import pandas as pd

df = pd.read_csv("top1mf.csv")
df = [list(row) for row in df.values]

b_down = 0
c_down = 0
r_down = 0

n_benign = 0
n_comp = 0

for row in df[1:-39]:
	if row[0] == 'compromised':
		n_comp += 1
		if row[3] == 9999:
			c_down += 1
	elif row[0] == 'benign':
		n_benign += 1
		if row[3] == 9999:
			b_down += 1

for row in df[-39:]:
	if row[3] == 9999:
		r_down += 1
		
print(str(r_down) + "/39 ransomwares down")
print(str(c_down) + "/" + str(n_comp) + " compromised down")
print(str(b_down) + "/" + str(n_benign) + " benign down")
print(str(r_down + c_down + b_down) + "/" + str(n_comp + n_benign + 39) + " total down")
