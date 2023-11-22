#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define SIZE 5

void prepareKeyMatrix(char key[], char keyMatrix[SIZE][SIZE])
{
    int i, j, k;
    char *keyPtr, *uniqueKey;

    for (i = 0; i < SIZE; i++)
        for (j = 0; j < SIZE; j++)
            keyMatrix[i][j] = 0;

    keyPtr = key;
    uniqueKey = (char *)malloc(strlen(key));

    for (i = 0, k = 0; i < strlen(key); i++)
        if (!strchr(uniqueKey, key[i]))
            uniqueKey[k++] = key[i];

    for (i = 0, k = 0; i < SIZE; i++)
        for (j = 0; j < SIZE; j++)
            if (k < strlen(uniqueKey))
                keyMatrix[i][j] = uniqueKey[k++];
}

void findPosition(char keyMatrix[SIZE][SIZE], char ch, int *row, int *col)
{
    int i, j;

    for (i = 0; i < SIZE; i++)
        for (j = 0; j < SIZE; j++)
            if (keyMatrix[i][j] == ch)
			{
                *row = i;
                *col = j;
                return;
            }
}

void encryptDigraph(char keyMatrix[SIZE][SIZE], char digraph[2], char encryptedDigraph[2])
{
    int row1, col1, row2, col2;

    findPosition(keyMatrix, digraph[0], &row1, &col1);
    findPosition(keyMatrix, digraph[1], &row2, &col2);

    if (row1 == row2)
	{
        encryptedDigraph[0] = keyMatrix[row1][(col1 + 1) % SIZE];
        encryptedDigraph[1] = keyMatrix[row2][(col2 + 1) % SIZE];
    }
    else if (col1 == col2)
	{
        encryptedDigraph[0] = keyMatrix[(row1 + 1) % SIZE][col1];
        encryptedDigraph[1] = keyMatrix[(row2 + 1) % SIZE][col2];
    }
    else
	{
	        encryptedDigraph[0] = keyMatrix[row1][col2];
        encryptedDigraph[1] = keyMatrix[row2][col1];
    }
}

void encryptPlayfair(char keyMatrix[SIZE][SIZE], char *input, char *output)
{
    int i;
    char digraph[2], encryptedDigraph[2];

    for (i = 0; i < strlen(input); i += 2)
	{
        digraph[0] = toupper(input[i]);
        digraph[1] = (i + 1 < strlen(input)) ? toupper(input[i + 1]) : 'X';
        encryptDigraph(keyMatrix, digraph, encryptedDigraph);
        output[i] = encryptedDigraph[0];
        output[i + 1] = encryptedDigraph[1];
    }
}

int main()
{
    char key[25];
    char keyMatrix[SIZE][SIZE];
    char input[100], output[100];
    
    printf("Enter Plain Text : ");
    scanf("%s", input);
	printf("Enter Key (up to 25 Characters) : ");
    scanf("%s", key);
	
    prepareKeyMatrix(key, keyMatrix);
    encryptPlayfair(keyMatrix, input, output);
    printf("Encrypted Text : %s\n", output);

    return 0;
}
