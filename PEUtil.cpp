#include "PEUtil.h"

PEUtil::PEUtil()
{
	this->fileBuff = NULL;
	this->fileSize = NULL;
	
	this->pDosHeader = NULL;
	this->pNtHeaders = NULL;
	this->pFileHeader = NULL;
	this->pOptionalHeader = NULL;
	this->pFirstSectionHeader = NULL;
}

PEUtil::~PEUtil()
{
	if (fileBuff)
	{
		delete[] fileBuff;
		fileBuff = NULL;
	}
}

/*
读取文件
*/
BOOL PEUtil::LoadFile(const char* path)
{

	// 打开文件
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == 0)
	{
		return FALSE;
	}
	
	// 读取文件
	fileSize = GetFileSize(hFile, NULL); 
	fileBuff = new char[fileSize];
	DWORD realReadBytes{ 0 };	// 文件真实大小

	if (!ReadFile(hFile, fileBuff, fileSize, &realReadBytes, NULL))
	{
		return FALSE;
	}

	// 初始化PE
	if (!InitPEInfo())
	{
		return FALSE;
	}

	// 关闭文件句柄
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return TRUE;
}

/*
初始化PE
*/
BOOL PEUtil::InitPEInfo()
{
	
	// 获取文件dos头
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuff;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		pDosHeader = NULL;
		return FALSE;
	}

	// 获取NT头
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + fileBuff);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		pNtHeaders = NULL;
		return FALSE;
	}

	// 获取标准PE头
	pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	if (!pFileHeader)
	{
		pFileHeader = NULL;
		return FALSE;
	}

	// 获取扩展PE头
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
	if (!pOptionalHeader)
	{
		pOptionalHeader = NULL;
		return FALSE;
	}

	// 获取第一个节表头
	pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	return TRUE;
}

/*
打印dos头
*/
void PEUtil::PrintDosHeader()
{
	if (!pDosHeader)
	{
		printf("PE DOS头错误，无法打开\n");
		return;
	}
	printf("\n====================PE DOS HEADER====================\n");
	printf("Dos头起始地址: %x\n", pDosHeader);
	printf("Magic: %x\t*e_lfanew: %x\n", pDosHeader->e_magic, pDosHeader->e_lfanew);

}

/*
打印NT头
*/
void PEUtil::PrintNtHeaders()
{
	if (!pNtHeaders)
	{
		printf("PE NT头错误，无法打开\n");
		return;
	}
	printf("\n====================PE NT HEADER====================\n");
	printf("NT头起始地址: %x\n", pNtHeaders);
	printf("*Signature: %x\n", pNtHeaders->Signature);
}

/*
打印标准PE头
*/
void PEUtil::PrintFileHeader()
{
	if (!pFileHeader)
	{
		printf("PE标准头错误，无法打开\n");
		return;
	}
	printf("\n====================PE FILE HEADER====================\n");
	printf("PE标准头起始地址: %x\n", pFileHeader);
	printf("Machine: %x\t*NumberOfSections(节表数量): %x\n", pFileHeader->Machine, pFileHeader->NumberOfSections);
	printf("TimeDateStamp: %x\t*SizeOfOptionalHeader(可选头大小): %x\n", pFileHeader->TimeDateStamp, pFileHeader->SizeOfOptionalHeader);
}

/*
打印扩展PE头
*/
void PEUtil::PrintOptionalHeader()
{
	if (!pOptionalHeader)
	{
		printf("PE扩展头错误，无法打开\n");
		return;
	}
	printf("\n====================PE OPTIONAL HEADER====================\n");
	printf("PE扩展头起始地址: %x\n", pOptionalHeader);
	printf("Magic: %x\tMajorLinderVersion: %x\tMinorLinkerVersion: %x\n", 
		pOptionalHeader->Magic, pOptionalHeader->MajorLinkerVersion, pOptionalHeader->MinorLinkerVersion);
	printf("SizeOfCode: %x\tSizeOfInitializedData: %x\tSizeOfUninitializedData: %x\n", 
		pOptionalHeader->SizeOfCode, pOptionalHeader->SizeOfInitializedData, pOptionalHeader->SizeOfUninitializedData);
	printf("*AddressOfEntryPoin(程序入口RVA): %x\n*BaseOfCode(代码块RVA): %x\n*BaseOfData(数据块RVA): %x\n",
		pOptionalHeader->AddressOfEntryPoint, pOptionalHeader->BaseOfCode, pOptionalHeader->BaseOfData);
	printf("*ImageBase(基址): %x\n*SectionAlignment(内存对齐值): %x\n*FileAlignment(文件对齐值): %x\n",
		pOptionalHeader->ImageBase, pOptionalHeader->SectionAlignment, pOptionalHeader->FileAlignment);
	printf("MajorOperatingSystemVersion: %x\tMinorOperatingSystemVersion: %x\tMajorImageVersion: %x\t\nMinorImageVersion: %x\tMajorSubsystemVersion: %x\tMinorSubsystemVersion: %x\n",
		pOptionalHeader->MajorOperatingSystemVersion, pOptionalHeader->MinorOperatingSystemVersion, 
		pOptionalHeader->MajorImageVersion, pOptionalHeader->MinorImageVersion,
		pOptionalHeader->MajorSubsystemVersion, pOptionalHeader->MinorSubsystemVersion);
	printf("SizeOfImage: %x\tSizeOfHeaders: %x\tChecksum: %x\n", 
		pOptionalHeader->SizeOfImage, pOptionalHeader->SizeOfHeaders, pOptionalHeader->CheckSum);
	printf("DllCharacteristics: %x\n", pOptionalHeader->DllCharacteristics);
	printf("ExportTable: %x\n", pOptionalHeader->DataDirectory[0]);
	printf("ImportTable: %x\n", pOptionalHeader->DataDirectory[1]);
}

/*
打印区段头
*/
void PEUtil::PrintSectionHeaders()
{
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;
	printf("\n====================SECTION HEADERS====================\n");
	printf("编号\tName\t\tVirtualSize\tVirtualAddress\tSizeOfRawData\tPointerToRawData\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy(name, pSectionHeader->Name, 8);
		printf("%d\t%s\t\t%x\t\t%x\t\t%x\t\t%x\n",
			i + 1, name, pSectionHeader->Misc, pSectionHeader->VirtualAddress,
			(pFirstSectionHeader + i)->SizeOfRawData, (pFirstSectionHeader + i)->PointerToRawData);
		/*printf("编号: %d\tSection name:%s\tMisc(内存中真实大小):%x\t\nVirtualAddress(内存中偏移值):%x\tSizeOfRawData(文件中对齐后的大小):%x\tPointerToRawData(文件中的偏移位置):%x\n",
			i + 1, name, pSectionHeader->Misc, pSectionHeader->VirtualAddress,
			(pFirstSectionHeader + i)->SizeOfRawData, (pFirstSectionHeader + i)->PointerToRawData);*/
		pSectionHeader++;
	}
}

/*
RVA 转 FOA
*/
DWORD PEUtil::RvaToFoa(DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;

	// 循环遍历区段
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		// rva >= 区段的首地址 && rva < 区段的首地址 + 区段的大小， 说明在此区段内
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{

			// FOA = 数据RVA - 区段RVA + 区段FOA
			return rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}

		// 下一个区段
		pSectionHeader++;
	}
	return rva;
}

/*
获取导出表
*/
void PEUtil::GetExportTable()
{

	printf("\n====================Export Section====================\n");
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;

	// 获取导出表的数据目录
	IMAGE_DATA_DIRECTORY exportDirectory = pOptionalHeader->DataDirectory[0];

	if (exportDirectory.VirtualAddress == 0)
	{
		printf("没有找到导出表！\n");
		return;
	}

	// 获取导出表FOA
	DWORD foa = RvaToFoa(exportDirectory.VirtualAddress);

	// 获取导出表首地址
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(foa + fileBuff);

	// 获取导出表dll名称
	char* dllName = RvaToFoa(pExport->Name) + fileBuff;
	printf("文件名称：%s\n", dllName);

	// 打印函数名称 函数地址->函数序号->函数名
	
	// 获取函数地址的首地址
	DWORD* functionAddress = (DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + fileBuff);

	// 获取函数序号的首地址
	DWORD* ordinalAddress = (DWORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + fileBuff);

	// 获取函数名的首地址
	DWORD* nameAddress = (DWORD*)(RvaToFoa(pExport->AddressOfNames) + fileBuff);

	// 遍历函数个数
	for (int i = 0; i < pExport->AddressOfFunctions; i++)
	{
		printf("函数地址：%p\n", *functionAddress++);

		// 根据函数地址找到函数序号
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (ordinalAddress[j] == i)
			{
				char* functionName = (RvaToFoa(nameAddress[j]) + fileBuff);
				printf("函数名称: %s\n", functionName);
				break;
			}
		}
	}
	
}

/*
获取导入表
*/
void PEUtil::GetImportTables()
{
	printf("\n====================Import Section====================\n");

	// 获取导入表
	IMAGE_DATA_DIRECTORY exportDirectory = pOptionalHeader->DataDirectory[1];
	if (exportDirectory.VirtualAddress == 0)
	{
		printf("没有找到导入表！\n");
		return;
	}

	// 获取导入表首地址
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR) (RvaToFoa(exportDirectory.VirtualAddress) + fileBuff);
	
	// 遍历导入表
	while (pImport->OriginalFirstThunk)
	{

		// 导入表名称
		char* name = RvaToFoa(pImport->Name) + fileBuff;
		printf("Name: %s\n", name);
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)(RvaToFoa(pImport->OriginalFirstThunk) + fileBuff);
		while (pThunkData->u1.AddressOfData)
		{
			// 判断是否为序号导入
			if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// 序号导入
				printf("序号：%d\n", pThunkData->u1.Ordinal & 0x7FFFFFF);
			}
			else
			{
				// 名称导入
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pThunkData->u1.AddressOfData) + fileBuff);
				printf("名称: %s\n", pImportByName->Name);
			}
			pThunkData++;
		}
		pImport++;
	}

}

/*
获取重定位表
*/
void PEUtil::GetRelocation()
{

	// 获取重定位表目录
	IMAGE_DATA_DIRECTORY relocationDirectory = pOptionalHeader->DataDirectory[5];

	// 获取重定位表首地址
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(relocationDirectory.VirtualAddress) + fileBuff);

	while (1)
	{
		if (pRelocation->VirtualAddress == 0) 
		{
			break;
		}

		// 计算出有多少小格子
		DWORD blockNum = (pRelocation->SizeOfBlock - 8) / 2;

		// 定义指针指向第一个小格子的首地址
		WORD* pBlock = (WORD*)(pRelocation + 4);

		// 循环遍历小格子
		for (int i = 0; i < blockNum; i++)
		{

			// 判断是否要修复，高4位为3  3000 0000
			if ((*pBlock & 0x3000) == 0x3000)
			{

				// 取低12位
				WORD low12Bit = *pBlock & 0x0FFF;
				DWORD rva = low12Bit + pRelocation->VirtualAddress;
				printf("RVA=%.8x\n", rva);
			}
			pBlock++;
		}

		// 指针指向下一个大块儿的首地址
		pRelocation = pRelocation + pRelocation->SizeOfBlock;
	}

}

/*
打印PE全部信息
*/
void PEUtil::PrintPEInfo()
{
	this->PrintDosHeader();
	this->PrintNtHeaders();
	this->PrintFileHeader();
	this->PrintOptionalHeader();
	this->PrintSectionHeaders();
	this->GetExportTable();
	this->GetImportTables();
	this->GetRelocation();

}