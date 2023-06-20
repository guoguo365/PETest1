#pragma once
#include <Windows.h>
#include <iostream>

class PEUtil
{
public:
	PEUtil();
	~PEUtil();

	/*
	��ȡ�ļ�
	*/
	BOOL LoadFile(const char* path);

	/*
	��ӡDOSͷ
	*/
	void PrintDosHeader();

	/*
	��ӡNTͷ
	*/
	void PrintNtHeaders();

	/*
	��ӡ��׼PEͷ
	*/
	void PrintFileHeader();

	/*
	��ӡ��չPEͷ
	*/
	void PrintOptionalHeader();

	/*
	��ӡ����ͷ
	*/
	void PrintSectionHeaders();

	/*
	RVAתFOA
	*/
	DWORD RvaToFoa(DWORD rva);

	/*
	��ȡ������
	*/
	void GetExportTable();

	/*
	��ȡ�����
	*/
	void GetImportTables();

	/*
	* ��ȡ�ض�λ��
	*/
	void GetRelocation();

	/*
	��ӡPE��Ϣ
	*/
	void PrintPEInfo();

private:

	// �ļ�������
	char* fileBuff;

	// �ļ���С
	DWORD fileSize;

	// DOSͷ
	PIMAGE_DOS_HEADER pDosHeader;

	// NTͷ
	PIMAGE_NT_HEADERS pNtHeaders;

	// ��׼PEͷ
	PIMAGE_FILE_HEADER pFileHeader;

	// ��չPEͷ
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;

	// ��һ���ڱ�ͷ
	PIMAGE_SECTION_HEADER pFirstSectionHeader;

	/*
	��ʼ��PE
	*/
	BOOL InitPEInfo();
};