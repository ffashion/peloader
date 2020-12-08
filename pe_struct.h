#include <stdint.h>
#include "data_dir.h"
#define IMAGE_SIZEOF_SHORT_NAME 8
#define MAX_SECTION 20
//offset_address 第一层是自己本机的地址(64位)
typedef struct offset_address{
    struct elf_dos *dos_offset;
    struct elf_nt *nt_offset;
    struct image_file_header *pe_offset ;
    struct image_option_file_header *ope_offset;
    struct image_section_header *section_table_offset[MAX_SECTION];
    char *section_offset[MAX_SECTION];
} offset_address;
// //*表示一些比较重要的字段

union misc_t{
    uint32_t virtual_address;
    uint32_t virtual_size;
};
//8个字节
struct image_data_dict
{
    uint32_t virtual_address;
    uint32_t size; //记录此目录大小, 可以随便修改，没啥用
};

//20字节
struct image_file_header
{
    uint16_t machine;                   //*
    uint16_t number_of_section;         //*
    uint32_t time_date_stamp;           //*
    uint32_t pointer_to_symbolTable;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;   //*
    uint16_t characteristic;            //*
};

//224==E0==16x14
struct image_option_file_header
{
    uint16_t magic;                         //*
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;                  //*
    uint32_t SizeOfInitializedData;         //*
    uint32_t SizeOfUninitializedData;       //*
    uint32_t address_of_entry_point;           //*
    uint32_t BaseOfCode;                    //*
    uint32_t BaseOfData;                    //*
    uint32_t image_base;                     //*
    uint32_t section_alignment;              //*
    uint32_t file_alignment;                //*
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t size_of_image;                   //*
    uint32_t size_of_headers;                 //*
    uint32_t check_sum;                      //*
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;            //*
    uint32_t SizeOfStackCommit;             //*
    uint32_t SizeOfHeapReserve;             //*
    uint32_t SizeOfHeapCommit;              //*
    uint32_t LoaderFlags;
    uint32_t number_of_rva_and_sizes;       //rva = relative virtual address
    struct image_data_dict data_dict[16];
};

//248字节
struct elf_nt
{
    uint32_t signature;
    struct image_file_header pe_header;
    struct image_option_file_header optional_pe_header;
};

//64字节
struct elf_dos
{
    uint16_t e_magic; //*
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew; //* 存储的值是相对于文件开始，根据此值可以找到NT头
};

//40字节
struct image_section_header{
    uint8_t name[IMAGE_SIZEOF_SHORT_NAME]; //*
    union misc_t misc;              //*节在没有文件对齐下内存中真实的大小
    uint32_t virtual_address;       //*节在内存中偏移的地址
    uint32_t size_of_raw_data;      //*节在文件对齐后的大小
    uint32_t pointer_to_raw_data;   //*
    uint32_t pointer_to_relocations;//指向重定位表
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};

struct  exeFile{
    struct elf_dos elf_dos;
    struct elf_nt elf_nt;
};

uint32_t rva2foa(offset_address *base_address,uint32_t rva);
uint16_t get_section_table_spare_size(offset_address *base_address);