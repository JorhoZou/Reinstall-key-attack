#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#define SECTIONSIZE 48

char p1[SECTIONSIZE+1] = { 0 };
char p2[SECTIONSIZE+1] = { 0 };
char stream[SECTIONSIZE+1] = { 0 };
int k;
int countnum;

int islegal(char x)
{
	int t;
	if (x == 'P' || x == 'O' || x == 'S' || x == 'T' || x == 'G' || x == 'E' || x == 'H' || x == 'I' || x == 'N' || x == 'U') t = 1;
	else t = 0;

	return t;
}

int filter()
{
	int i;
	
	for(i=0;i<SECTIONSIZE;i++)
	{
		if(p2[i]=='I'&&(i<(SECTIONSIZE-strlen("INPUT"))))
		{
			if(p2[i+1]!='N'||p2[i+2]!='P'||p2[i+3]!='U'||p2[i+4]!='T') return 0;
			else  continue;
		}
		
		if(p2[i]=='H'&&(i<(SECTIONSIZE-strlen("HTTP"))))
		{
			if(p2[i+1]!='T'||p2[i+2]!='T'||p2[i+3]!='P') return 0;
			else  continue;
		}
		
		if(p2[i]=='G'&&(i<(SECTIONSIZE-strlen("GET"))))
		{
			if(p2[i+1]!='E'||p2[i+2]!='T') return 0;
			else continue;
		}
		
		if(p2[i]=='S'&&(i<(SECTIONSIZE-strlen("ST")&&(i>=strlen("PO")))))
		{
			if(p2[i-2]!='P'||p2[i-1]!='O'||p2[i+1]!='T') return 0;
			else continue;
		}
	}
	
	return 1;
}

int dictionary(int start)
{
	//printf("%d\n", start);
	int count = 0;
	if (start == SECTIONSIZE) //recursive export
	{
		if(filter()) //check whether p2 is semantic(filter some p2)
		{
			printf("%s	%s\n",p1,p2);
		}
		return 1;
	}
	else if (start < SECTIONSIZE && start >(SECTIONSIZE - strlen("output"))) //maybe not an intact word, so judge by single letter
	{
		if (islegal('P'^stream[start]))
		{
			p1[start] = 'P';
			p2[start] = 'P'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('O'^stream[start]))
		{
			p1[start] = 'O';
			p2[start] = 'O'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('S'^stream[start]))
		{
			p1[start] = 'S';
			p2[start] = 'S'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('T'^stream[start]))
		{
			p1[start] = 'T';
			p2[start] = 'T'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('G'^stream[start]))
		{
			p1[start] = 'G';
			p2[start] = 'G'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('E'^stream[start]))
		{
			p1[start] = 'E';
			p2[start] = 'E'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('H'^stream[start]))
		{
			p1[start] = 'H';
			p2[start] = 'H'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('I'^stream[start]))
		{
			p1[start] = 'I';
			p2[start] = 'I'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('N'^stream[start]))
		{
			p1[start] = 'N';
			p2[start] = 'N'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}

		if (islegal('U'^stream[start]))
		{
			p1[start] = 'U';
			p2[start] = 'U'^stream[start];
			countnum = dictionary(start + 1);
			if (countnum) count += countnum;
		}
	} 
	else
	{
		//maybe "HTTP"
		if (islegal('H'^stream[start]) && islegal('T'^stream[start + 1]) && islegal('T'^stream[start + 2]) && islegal('P'^stream[start + 3]))
		{
			p1[start] = 'H';
			p1[start + 1] = 'T';
			p1[start + 2] = 'T';
			p1[start + 3] = 'P';
			p2[start] = 'H'^stream[start];
			p2[start + 1] = 'T'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			p2[start + 3] = 'P'^stream[start + 3];
			countnum = dictionary(start + 4);
			if (countnum) count += countnum;
		}
		//maybe "POST"
		if (islegal('P'^stream[start]) && islegal('O'^stream[start + 1]) && islegal('S'^stream[start + 2]) && islegal('T'^stream[start + 3]))
		{
			p1[start] = 'P';
			p1[start + 1] = 'O';
			p1[start + 2] = 'S';
			p1[start + 3] = 'T';
			p2[start] = 'P'^stream[start];
			p2[start + 1] = 'O'^stream[start + 1];
			p2[start + 2] = 'S'^stream[start + 2];
			p2[start + 3] = 'T'^stream[start + 3];
			countnum = dictionary(start + 4);
			if (countnum) count += countnum;
		}
		//maybe "GET"
		if (islegal('G'^stream[start]) && islegal('E'^stream[start + 1]) && islegal('T'^stream[start + 2]))
		{
			p1[start] = 'G';
			p1[start + 1] = 'E';
			p1[start + 2] = 'T';
			p2[start] = 'G'^stream[start];
			p2[start + 1] = 'E'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			countnum = dictionary(start + 3);
			if (countnum) count += countnum;
		}
		//maybe "INPUT" 
		if (islegal('I'^stream[start]) && islegal('N'^stream[start + 1]) && islegal('P'^stream[start + 2]) && islegal('U'^stream[start + 3]) && islegal('T'^stream[start + 4]))
		{
			p1[start] = 'I';
			p1[start + 1] = 'N';
			p1[start + 2] = 'P';
			p1[start + 3] = 'U';
			p1[start + 4] = 'T';
			p2[start] = 'I'^stream[start];
			p2[start + 1] = 'N'^stream[start + 1];
			p2[start + 2] = 'P'^stream[start + 2];
			p2[start + 3] = 'U'^stream[start + 3];
			p2[start + 4] = 'T'^stream[start + 4];
			countnum = dictionary(start + 5);
			if (countnum) count += countnum;
		}
		//maybe "OUTPUT"
		if (islegal('O'^stream[start]) && islegal('U'^stream[start + 1]) && islegal('T'^stream[start + 2]) && islegal('P'^stream[start + 3]) && islegal('U'^stream[start + 4]) && islegal('T'^stream[start + 5]))
		{
			p1[start] = 'O';
			p1[start + 1] = 'U';
			p1[start + 2] = 'T';
			p1[start + 3] = 'P';
			p1[start + 4] = 'U';
			p1[start + 5] = 'T';
			p2[start] = 'O'^stream[start];
			p2[start + 1] = 'U'^stream[start + 1];
			p2[start + 2] = 'T'^stream[start + 2];
			p2[start + 3] = 'P'^stream[start + 3];
			p2[start + 4] = 'U'^stream[start + 4];
			p2[start + 5] = 'T'^stream[start + 5];
			countnum = dictionary(start + 6);
			if (countnum) count += countnum;
		}
	}
	return count;
}

int main()
{					  
	char test1[SECTIONSIZE+1] = "POSTGETHTTPINPUTGETPOSTGETHTTPINPUTGETHTTPOUTPUT";
	char test2[SECTIONSIZE+1] = "INPUTOUTPUTGETGETINPUTOUTPUTGETGETHTTPPOSTPOSTHT";
	int i;

	for (i = 0; i<strlen(test1); i++) stream[i] = test1[i] ^ test2[i];
	printf("%s\n",stream);
	int count;
	count = dictionary(0);
	/*for (int i = 0; i < strlen(test1); i++)
	putchar(p1[i]);
	printf("\n");*/
	//printf("%s\n", p1);
	//printf("%s\n", p2);
	printf("count: %d\n", count);

	system("pause");
	return 0;
}
