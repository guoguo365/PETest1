#include "PEUtil.h"

int main()
{
	PEUtil peUtil;
	if (!peUtil.LoadFile("E:\\Temp\\TestDLL.dll"))
	{
		printf("��ȡ�ļ�ʧ��!\n");
	}
	peUtil.PrintPEInfo();

	system("pause");
 	return 0;
}