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
��ȡ�ļ�
*/
BOOL PEUtil::LoadFile(const char* path)
{

	// ���ļ�
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == 0)
	{
		return FALSE;
	}
	
	// ��ȡ�ļ�
	fileSize = GetFileSize(hFile, NULL); 
	fileBuff = new char[fileSize];
	DWORD realReadBytes{ 0 };	// �ļ���ʵ��С

	if (!ReadFile(hFile, fileBuff, fileSize, &realReadBytes, NULL))
	{
		return FALSE;
	}

	// ��ʼ��PE
	if (!InitPEInfo())
	{
		return FALSE;
	}

	// �ر��ļ����
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return TRUE;
}

/*
��ʼ��PE
*/
BOOL PEUtil::InitPEInfo()
{
	
	// ��ȡ�ļ�dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)fileBuff;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		pDosHeader = NULL;
		return FALSE;
	}

	// ��ȡNTͷ
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + fileBuff);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		pNtHeaders = NULL;
		return FALSE;
	}

	// ��ȡ��׼PEͷ
	pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeaders->FileHeader;
	if (!pFileHeader)
	{
		pFileHeader = NULL;
		return FALSE;
	}

	// ��ȡ��չPEͷ
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
	if (!pOptionalHeader)
	{
		pOptionalHeader = NULL;
		return FALSE;
	}

	// ��ȡ��һ���ڱ�ͷ
	pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	return TRUE;
}

/*
��ӡdosͷ
*/
void PEUtil::PrintDosHeader()
{
	if (!pDosHeader)
	{
		printf("PE DOSͷ�����޷���\n");
		return;
	}
	printf("\n====================PE DOS HEADER====================\n");
	printf("Dosͷ��ʼ��ַ: %x\n", pDosHeader);
	printf("Magic: %x\t*e_lfanew: %x\n", pDosHeader->e_magic, pDosHeader->e_lfanew);

}

/*
��ӡNTͷ
*/
void PEUtil::PrintNtHeaders()
{
	if (!pNtHeaders)
	{
		printf("PE NTͷ�����޷���\n");
		return;
	}
	printf("\n====================PE NT HEADER====================\n");
	printf("NTͷ��ʼ��ַ: %x\n", pNtHeaders);
	printf("*Signature: %x\n", pNtHeaders->Signature);
}

/*
��ӡ��׼PEͷ
*/
void PEUtil::PrintFileHeader()
{
	if (!pFileHeader)
	{
		printf("PE��׼ͷ�����޷���\n");
		return;
	}
	printf("\n====================PE FILE HEADER====================\n");
	printf("PE��׼ͷ��ʼ��ַ: %x\n", pFileHeader);
	printf("Machine: %x\t*NumberOfSections(�ڱ�����): %x\n", pFileHeader->Machine, pFileHeader->NumberOfSections);
	printf("TimeDateStamp: %x\t*SizeOfOptionalHeader(��ѡͷ��С): %x\n", pFileHeader->TimeDateStamp, pFileHeader->SizeOfOptionalHeader);
}

/*
��ӡ��չPEͷ
*/
void PEUtil::PrintOptionalHeader()
{
	if (!pOptionalHeader)
	{
		printf("PE��չͷ�����޷���\n");
		return;
	}
	printf("\n====================PE OPTIONAL HEADER====================\n");
	printf("PE��չͷ��ʼ��ַ: %x\n", pOptionalHeader);
	printf("Magic: %x\tMajorLinderVersion: %x\tMinorLinkerVersion: %x\n", 
		pOptionalHeader->Magic, pOptionalHeader->MajorLinkerVersion, pOptionalHeader->MinorLinkerVersion);
	printf("SizeOfCode: %x\tSizeOfInitializedData: %x\tSizeOfUninitializedData: %x\n", 
		pOptionalHeader->SizeOfCode, pOptionalHeader->SizeOfInitializedData, pOptionalHeader->SizeOfUninitializedData);
	printf("*AddressOfEntryPoin(�������RVA): %x\n*BaseOfCode(�����RVA): %x\n*BaseOfData(���ݿ�RVA): %x\n",
		pOptionalHeader->AddressOfEntryPoint, pOptionalHeader->BaseOfCode, pOptionalHeader->BaseOfData);
	printf("*ImageBase(��ַ): %x\n*SectionAlignment(�ڴ����ֵ): %x\n*FileAlignment(�ļ�����ֵ): %x\n",
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
��ӡ����ͷ
*/
void PEUtil::PrintSectionHeaders()
{
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;
	printf("\n====================SECTION HEADERS====================\n");
	printf("���\tName\t\tVirtualSize\tVirtualAddress\tSizeOfRawData\tPointerToRawData\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		char name[9]{ 0 };
		memcpy(name, pSectionHeader->Name, 8);
		printf("%d\t%s\t\t%x\t\t%x\t\t%x\t\t%x\n",
			i + 1, name, pSectionHeader->Misc, pSectionHeader->VirtualAddress,
			(pFirstSectionHeader + i)->SizeOfRawData, (pFirstSectionHeader + i)->PointerToRawData);
		/*printf("���: %d\tSection name:%s\tMisc(�ڴ�����ʵ��С):%x\t\nVirtualAddress(�ڴ���ƫ��ֵ):%x\tSizeOfRawData(�ļ��ж����Ĵ�С):%x\tPointerToRawData(�ļ��е�ƫ��λ��):%x\n",
			i + 1, name, pSectionHeader->Misc, pSectionHeader->VirtualAddress,
			(pFirstSectionHeader + i)->SizeOfRawData, (pFirstSectionHeader + i)->PointerToRawData);*/
		pSectionHeader++;
	}
}

/*
RVA ת FOA
*/
DWORD PEUtil::RvaToFoa(DWORD rva)
{
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;

	// ѭ����������
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		// rva >= ���ε��׵�ַ && rva < ���ε��׵�ַ + ���εĴ�С�� ˵���ڴ�������
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{

			// FOA = ����RVA - ����RVA + ����FOA
			return rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}

		// ��һ������
		pSectionHeader++;
	}
	return rva;
}

/*
��ȡ������
*/
void PEUtil::GetExportTable()
{

	printf("\n====================Export Section====================\n");
	PIMAGE_SECTION_HEADER pSectionHeader = pFirstSectionHeader;

	// ��ȡ�����������Ŀ¼
	IMAGE_DATA_DIRECTORY exportDirectory = pOptionalHeader->DataDirectory[0];

	if (exportDirectory.VirtualAddress == 0)
	{
		printf("û���ҵ�������\n");
		return;
	}

	// ��ȡ������FOA
	DWORD foa = RvaToFoa(exportDirectory.VirtualAddress);

	// ��ȡ�������׵�ַ
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(foa + fileBuff);

	// ��ȡ������dll����
	char* dllName = RvaToFoa(pExport->Name) + fileBuff;
	printf("�ļ����ƣ�%s\n", dllName);

	// ��ӡ�������� ������ַ->�������->������
	
	// ��ȡ������ַ���׵�ַ
	DWORD* functionAddress = (DWORD*)(RvaToFoa(pExport->AddressOfFunctions) + fileBuff);

	// ��ȡ������ŵ��׵�ַ
	DWORD* ordinalAddress = (DWORD*)(RvaToFoa(pExport->AddressOfNameOrdinals) + fileBuff);

	// ��ȡ���������׵�ַ
	DWORD* nameAddress = (DWORD*)(RvaToFoa(pExport->AddressOfNames) + fileBuff);

	// ������������
	for (int i = 0; i < pExport->AddressOfFunctions; i++)
	{
		printf("������ַ��%p\n", *functionAddress++);

		// ���ݺ�����ַ�ҵ��������
		for (int j = 0; j < pExport->NumberOfNames; j++)
		{
			if (ordinalAddress[j] == i)
			{
				char* functionName = (RvaToFoa(nameAddress[j]) + fileBuff);
				printf("��������: %s\n", functionName);
				break;
			}
		}
	}
	
}

/*
��ȡ�����
*/
void PEUtil::GetImportTables()
{
	printf("\n====================Import Section====================\n");

	// ��ȡ�����
	IMAGE_DATA_DIRECTORY exportDirectory = pOptionalHeader->DataDirectory[1];
	if (exportDirectory.VirtualAddress == 0)
	{
		printf("û���ҵ������\n");
		return;
	}

	// ��ȡ������׵�ַ
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR) (RvaToFoa(exportDirectory.VirtualAddress) + fileBuff);
	
	// ���������
	while (pImport->OriginalFirstThunk)
	{

		// ���������
		char* name = RvaToFoa(pImport->Name) + fileBuff;
		printf("Name: %s\n", name);
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)(RvaToFoa(pImport->OriginalFirstThunk) + fileBuff);
		while (pThunkData->u1.AddressOfData)
		{
			// �ж��Ƿ�Ϊ��ŵ���
			if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// ��ŵ���
				printf("��ţ�%d\n", pThunkData->u1.Ordinal & 0x7FFFFFF);
			}
			else
			{
				// ���Ƶ���
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFoa(pThunkData->u1.AddressOfData) + fileBuff);
				printf("����: %s\n", pImportByName->Name);
			}
			pThunkData++;
		}
		pImport++;
	}

}

/*
��ȡ�ض�λ��
*/
void PEUtil::GetRelocation()
{

	// ��ȡ�ض�λ��Ŀ¼
	IMAGE_DATA_DIRECTORY relocationDirectory = pOptionalHeader->DataDirectory[5];

	// ��ȡ�ض�λ���׵�ַ
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(relocationDirectory.VirtualAddress) + fileBuff);

	while (1)
	{
		if (pRelocation->VirtualAddress == 0) 
		{
			break;
		}

		// ������ж���С����
		DWORD blockNum = (pRelocation->SizeOfBlock - 8) / 2;

		// ����ָ��ָ���һ��С���ӵ��׵�ַ
		WORD* pBlock = (WORD*)(pRelocation + 4);

		// ѭ������С����
		for (int i = 0; i < blockNum; i++)
		{

			// �ж��Ƿ�Ҫ�޸�����4λΪ3  3000 0000
			if ((*pBlock & 0x3000) == 0x3000)
			{

				// ȡ��12λ
				WORD low12Bit = *pBlock & 0x0FFF;
				DWORD rva = low12Bit + pRelocation->VirtualAddress;
				printf("RVA=%.8x\n", rva);
			}
			pBlock++;
		}

		// ָ��ָ����һ���������׵�ַ
		pRelocation = pRelocation + pRelocation->SizeOfBlock;
	}

}

/*
��ӡPEȫ����Ϣ
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