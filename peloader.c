#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "pe_struct.h"
#define DOS_SIZE 64
#define PE_SIZE  20
char *default_file = "./test.exe";
//根据给定的alignment和value 返回value偏移后的结果
uint32_t get_alignment(uint32_t alignment,uint32_t value){
    if(value %alignment ==0){
        return value;
    }else{
        return alignment-(value % alignment) + value;
    }
    //return value%alignment ==0 ? value : alignment-(value % alignment) + value;
}
long get_file_size(char *file_name){
    FILE *fp = NULL;
    if((fp = fopen(file_name,"r")) == NULL){
        printf("获取文件失败");
        return -1;
    }
    //从文件末尾偏移，偏移0位
    fseek(fp,0,SEEK_END);
    long file_size = ftell(fp);//ftell()存储当前文件描述符的读取的偏移位置，这里就是文件末尾
    fclose(fp);
    return file_size;
}
char *set_file_to_buf(char *file_name){
    FILE *fp = NULL;
    long file_size;
    char *file_buf;
    if((fp = fopen(file_name,"rb")) == NULL){
        printf("准备好你的test.exe文件再来,或者指定exe文件\n");
        exit(-1);
    }
    file_size = get_file_size(file_name);
    printf("你的文件一共%ld(0x%lx)字节=%ldkb\n",file_size,file_size,file_size/1024);
    file_buf = malloc(file_size);
        
    
    memset(file_buf,0,file_size);
    rewind(fp);//设置当前的读取偏移位置为文件开头
    
    fread(file_buf,1,file_size,fp);


    //printf("%x\n",(uint16_t *)file_buf);

    fclose(fp);
    return file_buf;
    
}
//将file_buf的内容写到文件中
void set_buf_to_file(char *dest_file_name,char *file_buf,long file_size){
    FILE *fp = fopen(dest_file_name,"w");
    fwrite(file_buf,1,file_size,fp);
}
//将获取到的偏移地址写道offset_address 类型的变量中，如果flag是0,则以文件对齐方式读取，如果flag为1，则以内存对齐方式读取
//不需要返回指针，因为我们的base_address是在主函数创建的，此函数只是修改base_address中的内容
int get_offset_address(offset_address *base_address,char *buf,int flag){
   //注意这里的base_address参数 一定不能为空，一定要先将file_buf内容拷贝到image_buf中再执行此函数
   
   // base_address = malloc(sizeof(offset_address));
    if(flag == 0){
        base_address->dos_offset = (struct elf_dos*)buf;
        //注意这里不能使用base_address->dos_offset 必须使用buf ,可能buf是一个字节的,---------------强制转换之后就可以了
        base_address->nt_offset =  (struct  elf_nt*)((char*)base_address->dos_offset + base_address->dos_offset->e_lfanew);  
        base_address->pe_offset =  (struct  image_file_header*)((char *)base_address->nt_offset + sizeof(base_address->nt_offset->signature));
        base_address->ope_offset = (struct  image_option_file_header*)((char *)base_address->pe_offset + PE_SIZE);
        //分配所有的节表指针(包括空闲的)
        for(int i=0;i<=base_address->pe_offset->number_of_section-1+(get_section_table_spare_size(base_address)/40 -1);i++){
             base_address->section_table_offset[i] = (struct image_section_header*)((char *)base_address->ope_offset + base_address->pe_offset->size_of_optional_header+ i*sizeof(struct image_section_header));
             //printf("%d",base_address->section_table_offset[i]->pointer_to_raw_data);
             //base_address->section_offset[i]= (char *)base_address->dos_offset + base_address->section_table_offset[i]->pointer_to_raw_data;
        }

        return 0;
    }else if(flag == 1){
        //注意image刚开始进来是空的，所以不能和文件一样处理
        base_address->dos_offset = (struct elf_dos*)buf;
        //注意这里不能使用base_address->dos_offset 必须使用buf ,可能buf是一个字节的,---------------强制转换之后就可以了
        
        //这里的base_address->dos_offset->e_lfanew 为0
        base_address->nt_offset =  (struct  elf_nt*)((char*)base_address->dos_offset + \
        base_address->dos_offset->e_lfanew);

        base_address->pe_offset =  (struct  image_file_header*)((char *)base_address->nt_offset + sizeof(base_address->nt_offset->signature));
        base_address->ope_offset = (struct  image_option_file_header*)((char *)base_address->pe_offset + PE_SIZE);
        for(int i=0;i<=base_address->pe_offset->number_of_section-1;i++){
             base_address->section_table_offset[i] = (struct image_section_header*)((char *)base_address->ope_offset + base_address->pe_offset->size_of_optional_header+ i*sizeof(struct image_section_header));
             //base_address->section_offset[i]= base_address->section_table_offset[i]->virtual_address;
        }
        return 0;
    }
    return 0;
}
void *get_offset_rva2foa(offset_address *base_address,uint32_t rva){
    return (uint8_t *)base_address->dos_offset + rva2foa(base_address,rva);
}

int print_import_table(offset_address *base_address){
    struct image_import_dict *import_dict= (struct image_import_dict *)get_offset_rva2foa(base_address,base_address->ope_offset->data_dict[1].virtual_address);
    char *name = NULL;
    struct image_chunk_data* INT = NULL;
    int i =0;//for circul
    while(import_dict->name != 0){//最后的结构为全0结构,这里就只判断名字位置是否为0了，虽然这样写不准确，以后改
        
        import_dict = (struct image_import_dict *)get_offset_rva2foa(base_address,base_address->ope_offset->data_dict[1].virtual_address +sizeof(struct image_import_dict)*i);
        name = (char *)get_offset_rva2foa(base_address,import_dict->name);
        INT = (struct image_chunk_data*)get_offset_rva2foa(base_address,import_dict->original_first_thunk.original_first_thunk);
        printf("%s ",name);
        printf("%x ",INT->chunk_data.address_of_data);

        printf("\n");

        //加一个结构体的大小 为了while循环的判断
        import_dict = (struct image_import_dict *)get_offset_rva2foa(base_address,base_address->ope_offset->data_dict[1].virtual_address +sizeof(struct image_import_dict)*(i+1));
        i++;
    }
    // for(int i=0;i<=6;i++){
    //     import_dict[i] = (struct image_import_dict *)((uint8_t *)base_address->dos_offset + rva2foa(base_address,base_address->ope_offset->data_dict[1].virtual_address) +sizeof(struct image_import_dict)*i);
    //     name = (char *)((uint8_t *)base_address->dos_offset + rva2foa(base_address,import_dict[i]->name));
    //     printf("%s\n",name);
    // }
    return 0;
}
int print_relocation_dict(offset_address *base_address){
    //用于记录已循环的块大小
    //uint32_t recorded_block_size = 0;
    //内部2字节的地址数据
    if(base_address->ope_offset->data_dict[5].virtual_address ==0){
        printf("此dll/exe 无重定位表\n");
        return -1;
    }
    uint16_t *data = 0;
    struct image_base_relocation_dict *relocation_dict = (struct image_base_relocation_dict*)((char *)base_address->dos_offset + rva2foa(base_address,base_address->ope_offset->data_dict[5].virtual_address));
    
    //块大小为0退出循环
    while(relocation_dict->size_of_block != 0){
        //recorded_block_size = (uint8_t *)relocation_dict->size_of_block + recorded_block_size;
        data =(uint16_t *)((uint8_t *)relocation_dict + 8);
        printf("此页地址为:%x\n",relocation_dict->virtual_address);
        printf("此块大小为:%x\n",relocation_dict->size_of_block);
        for(uint32_t i=0;i<=(relocation_dict->size_of_block-8)/2 -1;i++){
            //判断最高字节是否为3 
            if((*(data+i) & 0x3000) == 0x3000){
                //输出去除最高位的3
                printf("%04x,%04x\n",*(data+i) & 0x0fff,(*(data+i) & 0x0fff) + relocation_dict->virtual_address);
            }
            
               
        }

        relocation_dict =  (struct image_base_relocation_dict*)((uint8_t *)relocation_dict +relocation_dict->size_of_block);

    }
    
    return 0;
}
int print_export_dict(offset_address *base_address){
    if(base_address->ope_offset->data_dict[0].virtual_address == 0){
        printf("此dll/exe 无导出表\n");
        return -1;
    }
    
    //取得导出表位置
    //这里char *强制转换可以想想
    //
    struct image_export_dict *export_dict = (struct image_export_dict *)((char *)base_address->dos_offset + rva2foa(base_address, base_address->ope_offset->data_dict[0].virtual_address));
    //取得函数名表地址
    uint32_t *address_of_name = (uint32_t *)((char *)base_address->dos_offset + rva2foa(base_address,export_dict->address_of_names));
    //获取函数标号地址
    uint16_t *address_of_oridnals = (uint16_t *)((char *)base_address->dos_offset + rva2foa(base_address,export_dict->address_of_name_ordinals));
    uint32_t *address_of_fun = (uint32_t *)((char *)base_address->dos_offset + rva2foa(base_address,export_dict->address_of_functions));
    char *fun_name = NULL;
    //exe中存储的oridnals
    uint16_t oridnals;
    //real_oridnals 存储oridinals加上base的值
    uint16_t real_oridnals;
    uint32_t fun_addr = 0x0;
    for(uint32_t i=0;i<=export_dict->number_of_names-1;i++){
        //取得函数名
        fun_name = (char *)((char *)base_address->dos_offset + rva2foa(base_address,*(address_of_name +i)));
        //获得函数符号名
        oridnals = *(address_of_oridnals+i);
        real_oridnals = oridnals + export_dict->base;
        //获得函数地址
        fun_addr = *(address_of_fun + oridnals);
        printf("%d:%016x:%s()\n",real_oridnals,fun_addr,fun_name);
    }
    return 0;
}
int print_data(offset_address *base_address){
    
    printf("------------DOS header ----------\n");
    printf("magic :%04x\n",base_address->dos_offset->e_magic); //先5a 再4d
    printf("cblp  :%04x\n",base_address->dos_offset->e_cblp);
    printf("cp    :%04x\n",base_address->dos_offset->e_cp);
    printf("lfanew :%08x\n",base_address->dos_offset->e_lfanew);

    printf("signature                :%08x\n",base_address->nt_offset->signature);
    printf("---------PE Header --------------\n");
    printf("machine                  :%04x\n",base_address->pe_offset->machine);
    printf("number of section        :%04x\n",base_address->pe_offset->number_of_section);
    printf("time data stamp          :%08x\n",base_address->pe_offset->time_date_stamp);
    printf("size of optional header  :%04x\n",base_address->pe_offset->size_of_optional_header);
    printf("characteris              :%04x\n",base_address->pe_offset->characteristic);

    printf("--------------Optional PE----------\n");
    printf("optional magic :%04x\n",base_address->ope_offset->magic);
    printf("size of code   :%08x\n",base_address->ope_offset->size_of_code);
    printf("section alignment: %08x\n",base_address->ope_offset->section_alignment);
    printf("file alignment :%08x\n",base_address->ope_offset->file_alignment);
    printf("base_address of entry point: %08x\n",base_address->ope_offset->address_of_entry_point);
    printf("image base     :%08x\n",base_address->ope_offset->image_base);
    printf("size of image  :%08x\n",base_address->ope_offset->size_of_image);
    printf("size of headers :%08x\n",base_address->ope_offset->size_of_headers);
    printf("number of rva and sizes :%08x\n",base_address->ope_offset->number_of_rva_and_sizes);

    printf("--------------Section Table-----------\n");
    //为了防止节的名字超过8个字节，所以创建一个9字节的空间
    char *name = malloc(9);

    for(int i=0;i<=base_address->pe_offset->number_of_section-1;i++){
        memcpy(name,&base_address->section_table_offset[i]->name,8);
        printf("section[%d] section name        :%s\n",i,name);
        printf("section[%d] pointer to raw data :%08x\n",i,base_address->section_table_offset[i]->pointer_to_raw_data);//节在文件中的偏移
        printf("section[%d] virtual address     :%08x\n",i,base_address->section_table_offset[i]->virtual_address);//节在内存中的偏移
        printf("section[%d] virtual size        :%08x\n",i,base_address->section_table_offset[i]->misc.virtual_size);//节的真实大小
        printf("section[%d] size of raw data    :%08x\n",i,base_address->section_table_offset[i]->size_of_raw_data);//节在文件对齐后的大小
        //printf("section[%d] base address :%08x\n",i,dos_buf->e_lfanew+4+PE_SIZE+OPE_SIZE+SECTION_SIZE*i);
        printf("此节空余空间为: %d\n",base_address->section_table_offset[i]->size_of_raw_data - base_address->section_table_offset[i]->misc.virtual_size);
    }
    for(uint32_t i=0;i<=base_address->ope_offset->number_of_rva_and_sizes-2;i++){
        printf("%s的地址为:0x%08x 大小为:%d字节\n",data_dir[i],base_address->ope_offset->data_dict[i].virtual_address,base_address->ope_offset->data_dict[i].size);
    }
    int spare_size = get_section_table_spare_size(base_address);
    printf("有%d字节可供新增节表使用,最多可以添加%d个节 建议只添加%d个节\n",spare_size,spare_size/40,spare_size/40 -1);
    

    print_export_dict(base_address);
    
    //打印重定位表,太多了
    //print_relocation_dict(base_address);
    
    print_import_table(base_address);
    return 0;
}

//给定file_buf 转换到image_buf
int file2image(offset_address *file_address, char *file_buf,char *image_buf){
    //获取整个头的大小(2种方式)
    int header_size = file_address->dos_offset->e_lfanew + 4 + PE_SIZE + file_address->pe_offset->size_of_optional_header  +  file_address->pe_offset->number_of_section*sizeof(struct image_section_header); // 没有对齐的大小
    //int header_size = file_address->ope_offset->size_of_headers; ;//按照文件对齐之后整个头的大小
    //printf("\nheader size---------%d\n",header_size);
    memcpy(image_buf,file_buf,header_size);
    for(int i=0;i<=file_address->pe_offset->number_of_section-1;i++){        
        //virtual address   此节在内存中的偏移地址
        //pointer_to_raw_data 此节在文件中的偏移地址
        //size_of_raw_data 节在文件对齐后的大小
        memcpy(image_buf + file_address->section_table_offset[i]->virtual_address,\
        file_buf+ file_address->section_table_offset[i]->pointer_to_raw_data,\
        file_address->section_table_offset[i]->size_of_raw_data
        );
    }
    
    return 0;
}
//给定image_buf 转换到file_buf
int image2file(offset_address *image_address,char *file_buf,char *image_buf){
    int header_size = image_address->ope_offset->size_of_headers; ;//按照文件对齐之后整个头的大小
    memset(file_buf,0,(size_t)get_file_size(default_file));
    
    memcpy(file_buf,image_buf,header_size);
    for(int i=0;i<=image_address->pe_offset->number_of_section-1;i++){
        memcpy(file_buf+image_address->section_table_offset[i]->pointer_to_raw_data,\
        image_buf + image_address->section_table_offset[i]->virtual_address,\
        image_address->section_table_offset[i]->size_of_raw_data
        );
    }

    
    return 0;
}

uint32_t rva2foa(offset_address *base_address,uint32_t rva){
    //uint32_t foa;  
    //判断是否在头里
    //RVA和整个头大小做比较
    if(rva <  base_address->ope_offset->size_of_headers){
        //foa = rva
        return rva;
    }
    //判断是否在各个节里
    for(int i=0;i<=base_address->pe_offset->number_of_section-1;i++){
        // virtual_address <=rva <= virtual_address + misc 此式判断rva是否在内存中的此节中
        if(base_address->section_table_offset[i]->virtual_address <= rva && rva \
        <= base_address->section_table_offset[i]->virtual_address + base_address->section_table_offset[i]->misc.virtual_size -1){
            //foa = rva - 此节在内存中的偏移地址 + 此节在文件中的偏移地址
            return rva - base_address->section_table_offset[i]->virtual_address + base_address->section_table_offset[i]->pointer_to_raw_data;
        }

    
    }
    return 0;
}
uint32_t foa2rva(offset_address *base_address,uint32_t foa){
    //内存对齐需要大于文件对齐
    uint32_t rva = 0;
    if(base_address->ope_offset->section_alignment >= base_address->ope_offset->file_alignment ){
        //判断是否在头里
        if(foa < base_address->ope_offset->size_of_headers){
           
            rva = foa;
            return rva;
        }
        for(int i=0;i<=base_address->pe_offset->number_of_section-1;i++){
            //判断是否在文件中的此节中
            //printf("%08x",)
            if(base_address->section_table_offset[i]->pointer_to_raw_data <= foa && foa <=  base_address->section_table_offset[i]->pointer_to_raw_data +  base_address->section_table_offset[i]->size_of_raw_data -1){
                
                rva = foa - base_address->section_table_offset[i]->pointer_to_raw_data + base_address->section_table_offset[i]->virtual_address;
                return rva;
            }
        }
    }else{
        printf("换个exe吧,转毛线");
        return 0;
    }
    return rva;
}
uint16_t get_section_table_spare_size(offset_address *base_address){
    return  base_address->ope_offset->size_of_headers - (base_address->dos_offset->e_lfanew + 4 + PE_SIZE + base_address->pe_offset->size_of_optional_header + base_address->pe_offset->number_of_section*40);
    
}
uint16_t *get_each_section_spare_size(offset_address *base_address,uint16_t *spare_size){
        for(int i=0;i<=base_address->pe_offset->number_of_section-1;i++){
            spare_size[i] = base_address->section_table_offset[i]->size_of_raw_data - base_address->section_table_offset[i]->misc.virtual_size;
        }
        return spare_size;
}

void exploit(offset_address *base_address){
    //base_address->section_table_offset[0]->pointer_to_raw_data + base_address->section_table_offset[0]->misc.virtual_size //从这个字节开始为空
    uint8_t shellcode[] = {0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00,0xe8,0x00,0x00,0x00,0x00,0xe9,0x00,0x00,0x00,0x00};
    //uint8_t shellcode[] = {0x6a,0x00,0x6a,0x00,0x00,0x00,0x00,0x6a,0x00,0x00,0x00,0x00,0x6a,0x00,0xe8,0x00,0x00,0x00,0x00,0xe9,0x00,0x00,0x00,0x00};//18字节
    //空闲空间的偏移地址(foa中)
    uint32_t in_file_spare_address_offset = base_address->section_table_offset[0]->pointer_to_raw_data + base_address->section_table_offset[0]->misc.virtual_size;
    // jmp_address = 调用函数的绝对地址 - 本指令地址的下一个指令所在地址   10表示本指令的开始位置 5表示下一指令开始位置
    uint32_t jmp_address =  0x76F71930 - (foa2rva(base_address,in_file_spare_address_offset + 8 + 5) + base_address->ope_offset->image_base);
    //uint32_t jmp_address =  0x76F71930 - (foa2rva(base_address,in_file_spare_address_offset + 14 + 5) + base_address->ope_offset->image_base);
    //call_address = 原本函数入口绝对地址 - 本指令的下一条地址所在绝对地址
    uint32_t call_address = (base_address->ope_offset->address_of_entry_point + base_address->ope_offset->image_base) -  (foa2rva(base_address,in_file_spare_address_offset + 8 + 5 +5) + base_address->ope_offset->image_base);
    //uint32_t call_address = (base_address->ope_offset->address_of_entry_point + base_address->ope_offset->image_base) -  (foa2rva(base_address,in_file_spare_address_offset + 14 + 5 +5) + base_address->ope_offset->image_base);
    //MZ所在的绝对地址 - 本指令所在下一条地址所在绝对地址
    //uint32_t string_address_title = (base_address->ope_offset->image_base) - (foa2rva(base_address,in_file_spare_address_offset +2 +5) + base_address->ope_offset->image_base);

    //修改entry point
    base_address->ope_offset->address_of_entry_point = foa2rva(base_address,in_file_spare_address_offset);
    //printf("OEP %04x\n",base_address->ope_offset->address_of_entry_point);
    memcpy(&shellcode[9],&jmp_address,4);
    memcpy(&shellcode[14],&call_address,4);
    // memcpy(&shellcode[15],&jmp_address,4);
    // //注意这里之前我写了21 会造成溢出,直接修改return 地址
    // memcpy(&shellcode[20],&call_address,4);
    
    // memcpy(&shellcode[3],&string_address_title,4);
    memcpy((void *)((char *)base_address->dos_offset + in_file_spare_address_offset),&shellcode,sizeof(shellcode));
    
}
void add_section(offset_address *base_address,char *name){
    //为了变量名短点 nos=number of section
    int nos = base_address->pe_offset->number_of_section;
    memcpy(&base_address->section_table_offset[nos]->name,name,8);
    base_address->section_table_offset[nos]->misc.virtual_size = 0x1000;
    base_address->section_table_offset[nos]->size_of_raw_data = 0x200;
    //virtual_address= 上个节的  [virtual_address + max(virtual_size,size_of_raw_data)] 再按内存对齐
    base_address->section_table_offset[nos]->virtual_address = get_alignment(0x1000,base_address->section_table_offset[nos-1]->virtual_address + \
    (base_address->section_table_offset[nos-1]->misc.virtual_size > base_address->section_table_offset[nos-1]->size_of_raw_data ?base_address->section_table_offset[nos-1]->misc.virtual_size : base_address->section_table_offset[nos-1]->size_of_raw_data)
    );
    base_address->section_table_offset[nos]->pointer_to_raw_data = base_address->section_table_offset[nos-1]->pointer_to_raw_data +  base_address->section_table_offset[nos-1]->size_of_raw_data;
    base_address->pe_offset->number_of_section++;
    base_address->ope_offset->size_of_image+=0x1000;
}

int main(int argc,char *argv[]){
    //记录file_buf此时多大
    long file_buf_size=0;
    char *file_buf = NULL;
    char *image_buf = NULL;
    char *src_file = NULL;
    offset_address *file_offset = NULL;
    offset_address *image_offset = NULL;
    
    //分配offset空间
    file_offset = malloc(sizeof(offset_address));
    image_offset = malloc(sizeof(offset_address));
    //分配file buf空间
    
    //函数内分配文件file_buf空间，并将文件数据读入file_buf中
    if(argc >= 2){
        src_file = argv[1];
    }else{
        src_file = default_file;
    }

    file_buf = set_file_to_buf(src_file);

    //设置file_buf_size，用于增加节,后面根据这个大小重新分配空间(realloc)，以及根据此值指定存到文件大小
    //file_buf_size =get_file_size(src_file) + 0x1000;
    file_buf_size =get_file_size(src_file);
    file_buf = realloc(file_buf,file_buf_size);
    
    //获取文件的偏移地址
    get_offset_address(file_offset,file_buf,0);
    
    //分配image_buf空间,并置0
    image_buf = malloc(file_offset->ope_offset->size_of_image); memset(image_buf,0,file_offset->ope_offset->size_of_image);
    
    //将file buf数据拷入image buf中
    //file2image(file_offset,file_buf,image_buf);
    //获取镜像的偏移地址
    get_offset_address(image_offset,image_buf,1);
    //add_section(file_offset,"test");
    print_data(file_offset);
    //print_data(image_offset);
    //此函数先对file_buf置空，然后再将image_buf按照file的格式拷贝到file_buf中
    //image2file(image_offset,file_buf,image_buf);
    

    exploit(file_offset);
    set_buf_to_file("pojie.exe",file_buf,file_buf_size);

    

    return 0;
}
