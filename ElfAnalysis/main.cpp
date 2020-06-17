#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>

#include "elf.h"

void help();
void file_header(FILE * fp);
void section_header(FILE * fp);


//字符串大写
char * my_strupr(char *str)
{
	char *orign = (char *)malloc(strlen(str) + 1);

	strcpy_s(orign, strlen(str) + 1, str);


	char * tmp = orign;
	while (*tmp) {
		*tmp = toupper(*tmp);
		tmp++;
	}


	return orign;
}


int main(int argc, char* argv[]) {
	if (argc < 3)
	{
		printf("invalid arguments\n");
		exit(0);
	}

	FILE *fp;
	errno_t err = 0;


	/*printf("1: %s\n", argv[0]);
	printf("2: %s\n", argv[1]);
	printf("3: %s\n", argv[2]);*/
	err = fopen_s(&fp, argv[2], "r");
	if (NULL == fp)
	{
		printf("open file fail\n");
		exit(0);
	}
	printf("-----------------------------------------------------------------------------------------------------\n");
	if (!strcmp(argv[1], "-h")) {
		file_header(fp);
	}
	else if (!strcmp(argv[1], "-S")) {
		section_header(fp);
	}

	//help();

	if (fp) {
		err = fclose(fp);
		if (err == 0) {
			printf("-----------------------------------------------------------------------------------------------------\n");
			//printf("The file closed\n");
		}
		else {
			printf("The file was not closed\n");
		}
	}
	return 0;
}

void section_header(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	printf("共有 %d 个节头, 节头表开始文件偏移为 0x%02x:\n", elf_head.e_shnum, elf_head.e_shoff);
	//Elf32_Shdr是描述每个节表的结构体，先通过Elf64_Shdr大小*elf_head.e_shnum节表数量得到要分配的内存
	//这是一个Elf32_Shdr数组
	Elf32_Shdr *shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * elf_head.e_shnum);
	if (shdr == NULL) {
		printf("shdr malloc failed\n");
		exit(0);
	}
	int a = 0;
	//移动fp位置
	a = fseek(fp, elf_head.e_shoff, SEEK_SET);
	if (a != 0) {
		printf("shdr fseek ERROR\n");
		exit(0);
	}

	a = fread(shdr, sizeof(Elf32_Shdr) * elf_head.e_shnum, 1, fp);
	if (a == 0) {
		printf("READ ERROR\n");
		exit(0);
	}
	//设置文件位置为给定流 stream 的文件的开头。
	rewind(fp);
	//定位到字符串节位置
	a = fseek(fp, (long)shdr[elf_head.e_shstrndx].sh_offset, SEEK_SET);
	if (a != 0) {
		printf("定位到字符串节表位置 %d \n", shdr[elf_head.e_shstrndx].sh_offset);
		printf("定位到字符串节表位置 shstrtab fseek ERROR \n");
		exit(0);
	}
	//得到字符串节表的长度（字节数）
	int sh_size = shdr[elf_head.e_shstrndx].sh_size;
	//char shstrtab[i];
	//分配容纳字符串节区的大小
	char *shstrtab = (char*)malloc(sizeof(char) * sh_size);
	char *temp = shstrtab;

	a = fread(shstrtab, sh_size, 1, fp);
	if (a == 0) {
		printf("READ ERROR\n");
		exit(0);
	}
	printf("\n各个section表信息:\n\n");
	printf("%-5s %-22s %-23s %-8s %-8s %-7s %-3s %-3s %-3s %-3s %-3s\n", "索引", "名称", "类型", "内存地址", "文件偏移", "大小", "ES", "标志", "链接", "附加信息", "对齐");
	for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
		temp = shstrtab;
		//shdr[shnum].sh_name字符串表的偏移
		temp = temp + shdr[shnum].sh_name;
		char *type_name = NULL;
		int has_free = 0;

		switch (shdr[shnum].sh_type)
		{
		case SHT_NULL:
			type_name = (char *)"NULL(无意义)";
			break;
		case SHT_PROGBITS:
			type_name = (char *)"PROGBITS(程序定义信息)";
			break;
		case SHT_SYMTAB:
			type_name = (char *)"SYMTAB(符号表)";
			break;
		case SHT_STRTAB:
			type_name = (char *)"STRTAB(字符串表)";
			break;
		case SHT_RELA:
			type_name = (char *)"RELA(重定位表项)";
			break;
		case SHT_HASH:
			type_name = (char *)"HASH(符号哈希表)";
			break;
		case SHT_DYNAMIC:
			type_name = (char *)"DYNAMIC(动态链接信息)";
			break;
		case SHT_NOTE:
			type_name = (char *)"NOTE(标记文件信息)";
			break;
		case SHT_NOBITS:
			type_name = (char *)"NOBITS(不占用文件空间)";
			break;
		case SHT_REL:
			type_name = (char *)"REL(重定位表项)";
			break;
		case SHT_SHLIB:
			type_name = (char *)"SHLIB(此节区被保留)";
			break;
		case SHT_DYNSYM:
			type_name = (char *)"DYNSYM(完整符号表)";
			break;
		default:
			type_name = my_strupr(temp);
			has_free = 1;
			break;
		}
		//标志解析
		char * flags = (char*)"";
		switch (shdr[shnum].sh_flags)
		{
		case SHF_WRITE:
			flags = (char *)"W";
			break;
		case SHF_ALLOC:
			flags = (char *)"A";
			break;
		case SHF_EXECINSTR:
			flags = (char *)"X";
			break;
		case SHF_WRITE|SHF_ALLOC:
			flags = (char *)"WA";
			break;
		case SHF_EXECINSTR | SHF_ALLOC:
			flags = (char *)"AX";
			break;
		case SHF_MASKPROC:
			flags = (char *)"MS";
			break;
		case SHF_LINK_ORDER| SHF_ALLOC:
			flags = (char *)"AL";
			break; 
		case 48:
			flags = (char *)"MS";
			break;
		default:
			break;
		}
		printf("%-5d %-22s %-23s %-8.08X %-8.06X %-5.06X  %-3.02X %-4s %-5d %-8d %-5d\n",
			shnum, temp, type_name, shdr[shnum].sh_addr,
			shdr[shnum].sh_offset, shdr[shnum].sh_size, shdr[shnum].sh_entsize, flags,
			shdr[shnum].sh_link, shdr[shnum].sh_info, shdr[shnum].sh_addralign);
		if (has_free)
			free(type_name);
	}
}

//打印ELF头部信息
void file_header(FILE * fp) {
	printf("ELF Header:\n");
	Elf32_Ehdr elf_head;

	int a;

	a = fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	if (a != 0) {
		//判断是否是ELF魔术
		if (elf_head.e_ident[EI_MAG0] != 0x7f && elf_head.e_ident[EI_MAG1] != 'E'
			&& elf_head.e_ident[EI_MAG2] != 'L' && elf_head.e_ident[EI_MAG3] != 'F') {
			printf("target is not ELF!\n");
			exit(0);
		}
		//打印Magic值
		printf(" %-53s %02X %-22.02X ELF \n", "Magic(魔术标识):",
			elf_head.e_ident[EI_MAG0], elf_head.e_ident[EI_MAG1], elf_head.e_ident[EI_MAG2], elf_head.e_ident[EI_MAG3]);
		//目标文件运行在目标机器的类别
		switch (elf_head.e_ident[EI_CLASS])
		{
		case ELFCLASSNONE:
			printf(" %-53s %-25.02X ELFCLASSNONE(非法类别)\n", "Class(运行平台):", elf_head.e_ident[EI_CLASS]);
			break;
		case ELFCLASS32:
			printf(" %-53s %-25.02X ELFCLASS32(32位目标)\n", "Class(运行平台):", elf_head.e_ident[EI_CLASS]);
			break;
		case ELFCLASS64:
			printf(" %-53s %-25.02X ELFCLASS64(64位目标)\n", "Class(运行平台):", elf_head.e_ident[EI_CLASS]);
			break;
		default:
			break;
		}

		//数据编码方式
		switch (elf_head.e_ident[EI_CLASS])
		{
		case ELFDATANONE:
			printf(" %-53s %-25.02X ELFDATANONE(非法数据编码)\n", "Data(数据编码方式):", elf_head.e_ident[EI_DATA]);
			break;
		case ELFDATA2LSB:
			printf(" %-53s %-25.02X ELFDATA2LSB(小端)\n", "Data(数据编码方式):", elf_head.e_ident[EI_DATA]);
			break;
		case ELFDATA2MSB:
			printf(" %-53s %-25.02X ELFDATA2MSB(大端)\n", "Data(数据编码方式):", elf_head.e_ident[EI_DATA]);
			break;
		default:
			break;
		}

		//此类值没有用到所有硬编码
		printf(" %-53s %-25.02X %s\n", "Version:", elf_head.e_ident[EI_VERSION], "1 (current)");
		printf(" %-53s %s\n", "OS/ABI:", "UNIX - System V");
		printf(" %-53s %s\n", "ABI Version:", "0");

		//elf文件的类型
		if (elf_head.e_type == ET_NONE) {
			printf(" %-53s %-25.02X ET_NONE(未知目标文件格式)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_REL) {
			printf(" %-53s %-25.02X ET_REL(可重定位文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_EXEC) {
			printf(" %-53s %-25.02X ET_EXEC(可执行文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_DYN) {
			printf(" %-53s %-25.02X ET_DYN(共享目标文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_CORE) {
			printf(" %-53s %-25.02X ET_CORE(Core 文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_LOPROC) {
			printf(" %-53s %-25.02X ET_LOPROC(特定处理器文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_HIPROC) {
			printf(" %-53s %-25.02X ET_HIPROC(特定处理器文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}
		else if (elf_head.e_type > 0xff00 && elf_head.e_type < 0xffff) {
			printf(" %-53s %-25.02X ET_LOPROC~ET_HIPROC(特定处理器文件)\n", "Type(elf文件类型):", elf_head.e_type);
		}

		//目标体系结构类型这里e_machine太多了我只给出部分
		switch (elf_head.e_machine)
		{
		case EM_NONE:
			printf(" %-53s %-25.02X EM_NONE(未指定)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_M32:
			printf(" %-53s %-25.02X EM_M32(AT&T WE 32100)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_SPARC:
			printf(" %-53s %-25.02X EM_SPARC(SPARC)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_386:
			printf(" %-53s %-25.02X EM_386(Intel 80386)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_68K:
			printf(" %-53s %-25.02X EM_68K(Motorola 68000)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_88K:
			printf(" %-53s %-25.02X EM_88K(Motorola 88000)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_860:
			printf(" %-53s %-25.02X EM_860(Intel 80860)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_MIPS:
			printf(" %-53s %-25.02X EM_MIPS(MIPS RS3000)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_ARM:
			printf(" %-53s %-25.02X EM_ARM(ARM)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		case EM_X86_64:
			printf(" %-53s %-25.02X EM_X86_64(64)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		default:
			printf(" %-53s %-25.02X others(预留)\n", "Machine(目标体系结构类型):", elf_head.e_machine);
			break;
		}

		printf(" %-53s %-25.02X %s\n", "Version:", elf_head.e_ident[EI_VERSION], "1");
		printf("\n");
		//e_entry程序入口地址,可执行文件的e_entry指向C库中的_start，而动态库.so中的进入点指向 call_gmon_start
		//作为动态链接库，e_entry入口地址是无意义的，因为程序被加载时，设定的跳转地址是动态连接器的地址，这个字段是可以被作为数据填充的。
		printf(" %-53s 0x%x\n", "Entry point address(程序入口地址):", elf_head.e_entry);

		printf(" %-53s %d (bytes into file) \n", "Start of program headers(程序头部表偏移地址):", elf_head.e_phoff);
		printf(" %-53s %d (bytes into file) \n", "Start of section headers(节区头部表偏移地址):", elf_head.e_shoff);
		printf(" %-53s 0x%-25.02X \n", "Flags(处理器的标志):", elf_head.e_flags);
		printf(" %-53s %d (bytes) \n", "Size of this header(ELF头的大小):", elf_head.e_ehsize);
		printf(" %-53s %d (bytes) \n", "Size of program headers(每个程序头部表的大小):", elf_head.e_phentsize);
		printf(" %-53s %d \n", "Number of program headers(程序头部表的数量):", elf_head.e_phnum);
		printf(" %-53s %d (bytes) \n", "Size of section headers(每个节区头部表的大小):", elf_head.e_shentsize);
		printf(" %-53s %d \n", "Number of section headers(节区头部表的数量):", elf_head.e_shnum);
		printf(" %-53s %d \n", "Section header string table index(节区字符串表位置):", elf_head.e_shstrndx);
	}
	else {
		printf("READ ERROR\n");
		exit(0);
	}
}

//打印帮助信息
void help()
{
	printf("这是Shark Chilli的解析器0.0,有疑问可以发送到我的邮箱:1243596620@qq.com\n");
	printf("-h            :头部信息\n");
	printf("-S            :节区表信息\n");
	printf("-s            :符号表信息\n");
	printf("-l            :程序头信息\n");
	printf("-r            :重定位表信息\n");
}
