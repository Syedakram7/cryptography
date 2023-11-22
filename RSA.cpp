#include<stdio.h>
#include<math.h>
int finde(int n){
int a[]={2,3,5,7,11,13,17,21,23};
for(int i=0;i<9;i++){
	if(n%a[i]!=0){
		return a[i];
	}
}
}
int findd(int e,int n){
	for(int i=1;i<=n;i++){
		int x=(e*i)%n;
		if(x==1){
			return i;
		}
	}
}
int main(){
	int p,q,m,n,n1,e,d,c,d1,ch;
	printf("1.Encryption \t2.Decryption\nENter your choice : ");
	scanf("%d",&ch);
	if(ch==1){
	printf("Enter the plain text : ");
	scanf("%d",&m);
	printf("Enter two prime numbers : ");
	scanf("%d",&p);
	scanf("%d",&q);
	n=p*q;
	n1=(p-1)*(q-1);
	e=finde(n1);
	d=findd(e,n1);
	printf("public key : %d  %d\nPrivate key : %d  %d",e,n,d,n);
	c=fmod(pow(m,e),n);
	printf("\nCipher text : %d",c);
}
	if(ch==2){
		printf("Enter private key pair : ");
		scanf("%d,%d",&d,&n);
		printf("ENter the cipher text : ");
		scanf("%d",&c);
		m=fmod(pow(c,d),n);
		printf("\nPlain text : %d",m);
	}
	
}
