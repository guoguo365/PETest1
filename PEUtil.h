#pragma once
#include <Windows.h>
#include <iostream>

class PEUtil
{
public:
	PEUtil();
	~PEUtil();

	/*
	读取文件
	*/
	BOOL LoadFile(const char* path);

	/*
	打印DOS头
	*/
	void PrintDosHeader();

	/*
	打印NT头
	*/
	void PrintNtHeaders();

	/*
	打印标准PE头
	*/
	void PrintFileHeader();

	/*
	打印扩展PE头
	*/
	void PrintOptionalHeader();

	/*
	打印区段头
	*/
	void PrintSectionHeaders();

	/*
	RVA转FOA
	*/
	DWORD RvaToFoa(DWORD rva);

	/*
	获取导出表
	*/
	void GetExportTable();

	/*
	获取导入表
	*/
	void GetImportTables();

	/*
	* 获取重定位表
	*/
	void GetRelocation();

	/*
	打印PE信息
	*/
	void PrintPEInfo();

private:

	// 文件缓冲区
	char* fileBuff;

	// 文件大小
	DWORD fileSize;

	// DOS头
	PIMAGE_DOS_HEADER pDosHeader;

	// NT头
	PIMAGE_NT_HEADERS pNtHeaders;

	// 标准PE头
	PIMAGE_FILE_HEADER pFileHeader;

	// 扩展PE头
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;

	// 第一个节表头
	PIMAGE_SECTION_HEADER pFirstSectionHeader;

	/*
	初始化PE
	*/
	BOOL InitPEInfo();
};