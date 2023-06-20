#include "PEUtil.h"

int main()
{
	PEUtil peUtil;
	if (!peUtil.LoadFile("E:\\Temp\\TestDLL.dll"))
	{
		printf("¶ÁÈ¡ÎÄ¼þÊ§°Ü!\n");
	}
	peUtil.PrintPEInfo();

	system("pause");
 	return 0;
}