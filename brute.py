Array = []
for i in range(65,91):
    Array.append(chr(i))

Input = input("Enter Plain Text : ")
Upper = Input.upper()

for Key in range(1,26):
    Cipher = ''
    
    for i in Upper:
        if(i == ' '):
            Cipher = Cipher + ' '
        else:
            Index = Array.index(i)
            Encrypt = (Index + Key) % 26
            Cipher = Cipher + Array[Encrypt]
    
    print("Encrypted Cipher Text When Key Value {0} : {1}".format(Key, Cipher))
