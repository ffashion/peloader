#include <stdint.h>
#define MAX_FUNCTION_NUMBER 100

struct image_export_dict{
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;  //指针类型(强制类型转换 uint32_t*)并且必须是32位
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
};
char *data_dir[] = {"导出表","导入表","资源表","异常信息表","安全证书表","重定位表","调试信息表","版权所有表","全局指针表","TLS表","加载配置表","绑定导入表","IAT表","延迟导入表","COM信息表","未使用"};
struct image_import_dict{
    union original_first_thunk_t{
        uint32_t characteristics;
        uint32_t original_first_thunk; //rva 指向 INT表 (image_chunk_data[])
    } original_first_thunk;
    uint32_t time_data_stamp;//如果时间戳为0 则表示IAT表未绑定,如果为全1 则表示IAT表已绑定(比如notebook.exe)
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;//rva指向 IAT表(image_chunk_data[])
};
struct image_chunk_data{
    union chunk_data_t{
        uint8_t  forwarder_string;
        uint32_t function;
        uint32_t ordinal;
        uint32_t address_of_data;//存储的是struct image_import_by_name类型的指针
    } chunk_data;
};
struct image_import_by_name{
    uint16_t hint;//当前函数在导出表的索引，可能为0，不一定准确，没啥用
    uint8_t name[1];//函数名字的一个字节，找到这个地址之后，要寻找整个字符串: 一直找到0为止
};



struct image_base_relocation_dict{
    uint32_t virtual_address;
    uint32_t size_of_block;
};

struct image_bound_import_dict{
    uint32_t time_data_stamp;
    uint16_t offset_module_name;
    uint16_t number_of_module_forwarder_refs;
};


