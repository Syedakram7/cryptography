a = {'A':0,'B':1,'C':2,'D':3,'E':4,'F':5,'G':6,'H':7,'I':8,'J':9,'K':10,'L':11,'M':12,'N':13,'O':14,'P':15,'Q':16,'R':17,'S':18,'T':19,'U':20,'V':21,'W':22,'X':23,'Y':24,'Z':25}
key = input("Enter the Key : ")
p = input("Enter plain Text : ")
k = ""
i = 0
for l in range(0,len(p)):
    if i < len(key):
        k = k + key[i]
        i = i + 1
    else:
        i = 0
        k = k + key[i]
        i = i + 1
        
print("Key is : "+k)

print(p)
print(k)

cipher = ""

for i in range(0,len(p)):
    pl = a.get(p[i])
    k1 = a.get(k[i])
    c = (pl + k1)%26
    keys = [q for q, v in a.items() if v == c][0]
    cipher = cipher + keys
print(cipher)
        

