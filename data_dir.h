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
// struct image_import_dict{
    
// };

struct image_base_relocation_dict{
    uint32_t virtual_address;
    uint32_t size_of_block;
};
