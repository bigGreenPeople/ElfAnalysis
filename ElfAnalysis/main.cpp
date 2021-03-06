#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>

#include "elf.h"

void help();
void file_header(FILE * fp);
void section_header(FILE * fp);
void dynsym_table(FILE * fp);
void program_table(FILE * fp);
void rel_table(FILE * fp);


int print_dynsym_table_entry(FILE * fp, char *dynstr, int dynsym_num);
int fp_move(FILE * fp, int offset);
char * my_strupr(char *str);
char * get_strtab(FILE * fp, Elf32_Shdr shdr);
Elf32_Rel * get_reltab(FILE * fp, Elf32_Shdr shdr);
Elf32_Sym * get_symtab(FILE * fp, Elf32_Shdr shdr);
const char * get_r_type(Elf32_Word info_type);

Elf32_Shdr * get_elf_shdr(FILE * fp, Elf32_Ehdr elf_head);
Elf32_Phdr * get_elf_phdr(FILE * fp, Elf32_Ehdr elf_head);

char * get_str_index(char * str, int index);

//得到字符串数组中第index个字符串
char * get_str_index(char * str, int index) {
	int temp = 0;
	char * temp_str = str;

	if (index == temp) {
		return str;
	}

	while (1)
	{
		if (!*temp_str) {
			temp++;
			if (temp == index) {
				return ++temp_str;
			}
		}

		temp_str++;
	}
}

const char * get_r_type(Elf32_Word info_type) {
	switch (info_type)
	{
	case 0: return "R_ARM_NONE";
	case 1: return "R_ARM_PC24"; /* Deprecated */
	case 2: return "R_ARM_ABS32";
	case 3: return "R_ARM_REL32";
	case 4: return "R_ARM_LDR_PC_G0"; /* Also R_ARM_PC13 */
	case 5: return "R_ARM_ABS16";
	case 6: return "R_ARM_ABS12";
	case 7: return "R_ARM_THM_ABS5";
	case 8: return "R_ARM_ABS8";
	case 9: return "R_ARM_SBREL32";
	case 10: return "R_ARM_THM_CALL"; /* Also R_ARM_THM_PC22 */
	case 11: return "R_ARM_THM_PC8";
	case 12: return "R_ARM_BREL_ADJ"; /* Also R_ARM_AMP_VCALL9 */
	case 13: return "R_ARM_TLS_DESC"; /* Also R_ARM_SWI24 */
	case 14: return "R_ARM_THM_SWI8"; /* Obsolete */
	case 15: return "R_ARM_XPC25"; /* Obsolete */
	case 16: return "R_ARM_THM_XPC22"; /* Obsolete */
	case 17: return "R_ARM_TLS_DTPMOD32";
	case 18: return "R_ARM_TLS_DTPOFF32";
	case 19: return "R_ARM_TLS_TPOFF32";
	case 20: return "R_ARM_COPY";
	case 21: return "R_ARM_GLOB_DAT";
	case 22: return "R_ARM_JUMP_SLOT";
	case 23: return "R_ARM_RELATIVE";
	case 24: return "R_ARM_GOTOFF32"; /* Also R_ARM_GOTOFF */
	case 25: return "R_ARM_BASE_PREL"; /* GNU R_ARM_GOTPC */
	case 26: return "R_ARM_GOT_BREL"; /* GNU R_ARM_GOT32 */
	case 27: return "R_ARM_PLT32"; /* Deprecated */
	case 28: return "R_ARM_CALL";
	case 29: return "R_ARM_JUMP24";
	case 30: return "R_ARM_THM_JUMP24";
	case 31: return "R_ARM_BASE_ABS";
	case 32: return "R_ARM_ALU_PCREL_7_0"; /* Obsolete */
	case 33: return "R_ARM_ALU_PCREL_15_8"; /* Obsolete */
	case 34: return "R_ARM_ALU_PCREL_23_15"; /* Obsolete */
	case 35: return "R_ARM_LDR_SBREL_11_0_NC"; /* Deprecated */
	case 36: return "R_ARM_ALU_SBREL_19_12_NC"; /* Deprecated */
	case 37: return "R_ARM_ALU_SBREL_27_20_CK"; /* Deprecated */
	case 38: return "R_ARM_TARGET1";
	case 39: return "R_ARM_SBREL31"; /* Deprecated. */
	case 40: return "R_ARM_V4BX";
	case 41: return "R_ARM_TARGET2";
	case 42: return "R_ARM_PREL31";
	case 43: return "R_ARM_MOVW_ABS_NC";
	case 44: return "R_ARM_MOVT_ABS";
	case 45: return "R_ARM_MOVW_PREL_NC";
	case 46: return "R_ARM_MOVT_PREL";
	case 47: return "R_ARM_THM_MOVW_ABS_NC";
	case 48: return "R_ARM_THM_MOVT_ABS";
	case 49: return "R_ARM_THM_MOVW_PREL_NC";
	case 50: return "R_ARM_THM_MOVT_PREL";
	case 51: return "R_ARM_THM_JUMP19";
	case 52: return "R_ARM_THM_JUMP6";
	case 53: return "R_ARM_THM_ALU_PREL_11_0";
	case 54: return "R_ARM_THM_PC12";
	case 55: return "R_ARM_ABS32_NOI";
	case 56: return "R_ARM_REL32_NOI";
	case 57: return "R_ARM_ALU_PC_G0_NC";
	case 58: return "R_ARM_ALU_PC_G0";
	case 59: return "R_ARM_ALU_PC_G1_NC";
	case 60: return "R_ARM_ALU_PC_G1";
	case 61: return "R_ARM_ALU_PC_G2";
	case 62: return "R_ARM_LDR_PC_G1";
	case 63: return "R_ARM_LDR_PC_G2";
	case 64: return "R_ARM_LDRS_PC_G0";
	case 65: return "R_ARM_LDRS_PC_G1";
	case 66: return "R_ARM_LDRS_PC_G2";
	case 67: return "R_ARM_LDC_PC_G0";
	case 68: return "R_ARM_LDC_PC_G1";
	case 69: return "R_ARM_LDC_PC_G2";
	case 70: return "R_ARM_ALU_SB_G0_NC";
	case 71: return "R_ARM_ALU_SB_G0";
	case 72: return "R_ARM_ALU_SB_G1_NC";
	case 73: return "R_ARM_ALU_SB_G1";
	case 74: return "R_ARM_ALU_SB_G2";
	case 75: return "R_ARM_LDR_SB_G0";
	case 76: return "R_ARM_LDR_SB_G1";
	case 77: return "R_ARM_LDR_SB_G2";
	case 78: return "R_ARM_LDRS_SB_G0";
	case 79: return "R_ARM_LDRS_SB_G1";
	case 80: return "R_ARM_LDRS_SB_G2";
	case 81: return "R_ARM_LDC_SB_G0";
	case 82: return "R_ARM_LDC_SB_G1";
	case 83: return "R_ARM_LDC_SB_G2";
	case 84: return "R_ARM_MOVW_BREL_NC";
	case 85: return "R_ARM_MOVT_BREL";
	case 86: return "R_ARM_MOVW_BREL";
	case 87: return "R_ARM_THM_MOVW_BREL_NC";
	case 88: return "R_ARM_THM_MOVT_BREL";
	case 89: return "R_ARM_THM_MOVW_BREL";
	case 90: return "R_ARM_TLS_GOTDESC";
	case 91: return "R_ARM_TLS_CALL";
	case 92: return "R_ARM_TLS_DESCSEQ";
	case 93: return "R_ARM_THM_TLS_CALL";
	case 94: return "R_ARM_PLT32_ABS";
	case 95: return "R_ARM_GOT_ABS";
	case 96: return "R_ARM_GOT_PREL";
	case 97: return "R_ARM_GOT_BREL12";
	case 98: return "R_ARM_GOTOFF12";
	case 99: return "R_ARM_GOTRELAX";
	case 100: return "R_ARM_GNU_VTENTRY";
	case 101: return "R_ARM_GNU_VTINHERIT";
	case 102: return "R_ARM_THM_JUMP11"; /* Also R_ARM_THM_PC11 */
	case 103: return "R_ARM_THM_JUMP8"; /* Also R_ARM_THM_PC9 */
	case 104: return "R_ARM_TLS_GD32";
	case 105: return "R_ARM_TLS_LDM32";
	case 106: return "R_ARM_TLS_LDO32";
	case 107: return "R_ARM_TLS_IE32";
	case 108: return "R_ARM_TLS_LE32";
	case 109: return "R_ARM_TLS_LDO12";
	case 110: return "R_ARM_TLS_LE12";
	case 111: return "R_ARM_TLS_IE12GP";
		/* 112-127 R_ARM_PRIVATE_<n> */
	case 128: return "R_ARM_ME_TOO"; /* Obsolete */
	case 129: return "R_ARM_THM_TLS_DESCSEQ16";
	case 130: return "R_ARM_THM_TLS_DESCSEQ32";
	case 131: return "R_ARM_THM_GOT_BREL12";
	case 132: return "R_ARM_THM_ALU_ABS_G0_NC";
	case 133: return "R_ARM_THM_ALU_ABS_G1_NC";
	case 134: return "R_ARM_THM_ALU_ABS_G2_NC";
	case 135: return "R_ARM_THM_ALU_ABS_G3";
		/* 136-159 Reserved for future allocation. */
	case 160: return "R_ARM_IRELATIVE";
		/* 161-255 Reserved for future allocation. */
	case 249: return "R_ARM_RXPC25";
	case 250: return "R_ARM_RSBREL32";
	case 251: return "R_ARM_THM_RPC22";
	case 252: return "R_ARM_RREL32";
	case 253: return "R_ARM_RABS32";
	case 254: return "R_ARM_RPC24";
	case 255: return "R_ARM_RBASE";
	default:
		return "";
	}
}


/*
	得到ELF节表数组
	需释放内存
*/
Elf32_Shdr * get_elf_shdr(FILE * fp, Elf32_Ehdr elf_head) {
	//Elf32_Shdr是描述每个节表的结构体，先通过Elf64_Shdr大小*elf_head.e_shnum节表数量得到要分配的内存
	Elf32_Shdr *shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * elf_head.e_shnum);
	memset(shdr, 0, sizeof(Elf32_Shdr) * elf_head.e_shnum);

	if (shdr == NULL) {
		printf("shdr malloc failed\n");
		return NULL;
	}

	int result = 0;
	//移动fp位置
	result = fseek(fp, elf_head.e_shoff, SEEK_SET);
	if (result != 0) {
		printf("shdr fseek ERROR\n");
		free(shdr);
		return NULL;
	}
	//读取数据
	result = fread(shdr, sizeof(Elf32_Shdr), elf_head.e_shnum, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(shdr);
		return NULL;
	}
	return shdr;
}


/*
	得到ELF段表数组
	需释放内存
*/
Elf32_Phdr * get_elf_phdr(FILE * fp, Elf32_Ehdr elf_head) {
	//Elf32_Shdr是描述每个节表的结构体，先通过Elf64_Shdr大小*elf_head.e_shnum节表数量得到要分配的内存
	Elf32_Phdr *phdr = (Elf32_Phdr*)malloc(sizeof(Elf32_Phdr) * elf_head.e_phnum);
	memset(phdr, 0, sizeof(Elf32_Phdr) * elf_head.e_phnum);

	if (phdr == NULL) {
		printf("phdr malloc failed\n");
		return NULL;
	}

	int result = 0;
	//移动fp位置
	result = fseek(fp, elf_head.e_phoff, SEEK_SET);
	if (result != 0) {
		printf("phdr fseek ERROR\n");
		free(phdr);
		return NULL;
	}
	//读取数据
	result = fread(phdr, sizeof(Elf32_Phdr), elf_head.e_phnum, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(phdr);
		return NULL;
	}
	return phdr;
}

/*
	得重定位表数组
	需释放内存
	shdr 一般是类型是 SHT_RELA或者SHT_REL
*/
Elf32_Rel * get_reltab(FILE * fp, Elf32_Shdr shdr) {
	//定位到重定位表位置
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}

	//得到重定位表的长度（字节数）
	int sh_size = shdr.sh_size;
	//char shstrtab[i];
	//分配容纳重定位表的大小
	Elf32_Rel *shreltab = (Elf32_Rel*)malloc(sizeof(Elf32_Rel) * sh_size);
	memset(shreltab, 0, sizeof(char) * sh_size);

	if (shreltab == NULL) {
		printf("分配内存 shreltab ERROR \n");
		return NULL;
	}

	int result;
	result = fread(shreltab, sh_size, 1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(shreltab);
		return NULL;
	}
	return shreltab;
}

/*
	得到.shstrtab或.dynstr的字符串
	需释放内存
	shdr 一般是.dynstr或者.shstrtab
*/
char * get_strtab(FILE * fp, Elf32_Shdr shdr) {

	//定位到字符串节位置
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}

	//得到字符串节表的长度（字节数）
	int sh_size = shdr.sh_size;
	//char shstrtab[i];
	//分配容纳字符串节区的大小
	char *shstrtab = (char*)malloc(sizeof(char) * sh_size);
	memset(shstrtab, 0, sizeof(char) * sh_size);

	if (shstrtab == NULL) {
		printf("分配内存 str ERROR \n");
		return NULL;
	}

	int result;
	result = fread(shstrtab, sh_size, 1, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(shstrtab);
		return NULL;
	}
	return shstrtab;
}


//移动fp  失败返回0
int fp_move(FILE * fp, int offset) {
	rewind(fp);
	int result;

	result = fseek(fp, offset, SEEK_SET);
	if (result != 0) {
		printf("fp_move ERROR \n");
		return 0;
	}
}

//打印符号表项
int print_dynsym_table_entry(FILE * fp, char *dynstr, int dynsym_num) {

	//开辟内存
	Elf32_Sym *psym = (Elf32_Sym*)malloc(sizeof(Elf32_Sym) *dynsym_num);
	memset(psym, 0, sizeof(Elf32_Sym) *dynsym_num);
	if (psym == NULL) {
		printf("psym malloc failed\n");
		return 0;
	}
	//读取符号表
	int result;
	result = fread(psym, sizeof(Elf32_Sym), dynsym_num, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(psym);
		return 0;
	}

	printf("%-5s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "Num", "Value", "大小", "类型", "绑定属性", "Vis", "Ndx", "名称");
	for (int dynsym_index = 0; dynsym_index < dynsym_num; dynsym_index++) {

		char * sym_type = (char *) "";
		switch (ELF32_ST_TYPE(psym[dynsym_index].st_info))
		{
		case STT_NOTYPE:
			sym_type = (char *)"NOTYPE";
			break;
		case STT_OBJECT:
			sym_type = (char *)"OBJECT";
			break;
		case STT_FUNC:
			sym_type = (char *)"FUNC";
			break;
		case STT_SECTION:
			sym_type = (char *)"SECTION";
			break;
		case STT_FILE:
			sym_type = (char *)"FILE";
			break;
		case STT_LOPROC:
			sym_type = (char *)"LOPROC";
			break;
		case STT_HIPROC:
			sym_type = (char *)"HIPROC";
			break;
		default:
			break;
		}

		char * sym_bind = (char *) "";
		switch (ELF32_ST_BIND(psym[dynsym_index].st_info))
		{
		case STB_LOCAL:
			sym_bind = (char *)"LOCAL";
			break;
		case STB_GLOBAL:
			sym_bind = (char *)"GLOBAL";
			break;
		case STB_WEAK:
			sym_bind = (char *)"WEAK";
			break;
		case STB_HIPROC:
			sym_bind = (char *)"HIPROC";
			break;
		default:
			break;
		}

		char * sym_vis = (char *) "";
		switch (ELF32_ST_VISIBILITY(psym[dynsym_index].st_other))
		{
		case STV_DEFAULT:
			sym_vis = (char *)"DEFAULT";
			break;
		case STV_INTERNAL:
			sym_vis = (char *)"INTERNAL";
			break;
		case STV_HIDDEN:
			sym_vis = (char *)"HIDDEN";
			break;
		case STV_PROTECTED:
			sym_vis = (char *)"PROTECTED";
			break;
		default:
			break;
		}

		char sym_ndx[10] = { 0 };
		switch (psym[dynsym_index].st_shndx)
		{
		case SHN_ABS:
			strcpy_s(sym_ndx, strlen("ABS") + 1, "ABS");
			break;
		case SHN_COMMON:
			strcpy_s(sym_ndx, strlen("COMMON") + 1, "COMMON");
			break;
		case SHN_UNDEF:
			strcpy_s(sym_ndx, strlen("UND") + 1, "UND");
			break;
		default:
			_itoa_s(psym[dynsym_index].st_shndx, sym_ndx, 10);
			break;
		}

		printf("%-5d %-8.08X %-8d %-8s %-8s %-8s %-8s %-8s\n",
			dynsym_index, psym[dynsym_index].st_value, psym[dynsym_index].st_size, sym_type, sym_bind, sym_vis
			, sym_ndx, dynstr + psym[dynsym_index].st_name);
	}

	free(psym);
	return 1;
}



int main(int argc, char* argv[]) {

	if (!strcmp(argv[1], "-help")) {
		help();
		exit(0);
	}

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
	err = fopen_s(&fp, argv[2], "rb");
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
	else if (!strcmp(argv[1], "-s")) {
		dynsym_table(fp);
	}
	else if (!strcmp(argv[1], "-l")) {
		program_table(fp);
	}
	else if (!strcmp(argv[1], "-r")) {
		rel_table(fp);
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

//解析重定位表
void rel_table(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	//这是一个段表数组
	Elf32_Phdr *phdr = get_elf_phdr(fp, elf_head);
	if (!phdr) {
		exit(0);
	}
	//这是一个Elf32_Shdr数组
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//得到字符串表信息
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}

	//得到符号字符串表信息
	//找到.dynstr表
	char * dynstr = NULL;
	char * temp = shstrtab;
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name字符串表的偏移
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynstr"))
		{
			dynstr = get_strtab(fp, shdr[shnum]);
			if (!dynstr) {
				exit(0);
			}
			break;
		}
	}

	//得到符号表信息
	Elf32_Sym * symtab = NULL;

	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name字符串表的偏移
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynsym"))
		{
			symtab= get_symtab(fp, shdr[shnum]);
		}
	}

	//循环找到重定位表
	for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
		if (shdr[shnum].sh_type == SHT_REL) {
			//重定位表大小
			int rel_num = shdr[shnum].sh_size / shdr[shnum].sh_entsize;
			printf(" 重定位表'%s' 起始位置:0x%X 包含%d个重定位项 \n", shstrtab + shdr[shnum].sh_name, shdr[shnum].sh_addr, rel_num);
			printf("%-10s %-10s %-15s %-10s %-10s\n", "重定位地址", "重定位信息", "重定位类型", "符号值", "符号名称");
			Elf32_Rel * reltab = get_reltab(fp, shdr[shnum]);


			for (int rel_index = 0; rel_index < rel_num; rel_index++) {


				printf("%-10.08X %-10.08X %-15s %-10.8x %-10s\n", reltab[rel_index].r_offset, reltab[rel_index].r_info,
					get_r_type(ELF32_R_TYPE(reltab[rel_index].r_info)),
					symtab[ELF32_R_SYM(reltab[rel_index].r_info)].st_value, get_str_index(dynstr,ELF32_R_SYM(reltab[rel_index].r_info)));
			}

			printf("\n");
			free(reltab);
		}

	}

	free(symtab);
	free(dynstr);
	free(phdr);
	free(shstrtab);
	free(shdr);
}

//解析段头表
void program_table(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	printf("共有 %d 个段头, 段头表开始文件偏移为 0x%02x:\n\n", elf_head.e_phnum, elf_head.e_phoff);
	//这是一个段表数组
	Elf32_Phdr *phdr = get_elf_phdr(fp, elf_head);
	if (!phdr) {
		exit(0);
	}
	//这是一个Elf32_Shdr数组
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//得到字符串表信息
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}
	char *temp = shstrtab;

	printf("\n各个Program表信息:\n");
	printf("%-5s %-20s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
		"", "类型", "文件偏移", "内存地址", "物理地址", "文件大小", "内存大小", "标志", "对齐");
	for (int phnum = 0; phnum < elf_head.e_phnum; phnum++) {

		char * type_name = (char *)"";
		switch (phdr[phnum].p_type)
		{
		case PT_NULL:
			type_name = (char *)"NULL(空段)";
			break;
		case PT_LOAD:
			type_name = (char *)"LOAD(可装载)";
			break;
		case PT_DYNAMIC:
			type_name = (char *)"DYNAMIC(动态链接信息)";
		case PT_INTERP:
			type_name = (char *)"INTERP(动态链接解释)";
			break;
		case PT_NOTE:
			type_name = (char *)"NOTE(专有的编译器信息)";
			break;
		case PT_SHLIB:
			type_name = (char *)"SHLIB(共享库)";
			break;
		case PT_GNU_STACK:
			type_name = (char *)"GNU_STACK";
			break;
		case PT_PHDR:
			type_name = (char *)"PHDR";
			break;
		case PT_GNU_RELRO:
			type_name = (char *)"GNU_RELRO";
			break;
		case PT_ARM_EXIDX:
			type_name = (char *)"EXIDX";
			break;
		default:
			break;
		}

		char * flag_name = (char *)"";
		switch (phdr[phnum].p_flags) {
		case PF_R:
			flag_name = (char *)"R";
			break;
		case PF_W:
			flag_name = (char *)"W";
			break;
		case PF_X:
			flag_name = (char *)"E";
			break;
		case PF_W | PF_X:
			flag_name = (char *)"WE";
			break;
		case PF_R | PF_W:
			flag_name = (char *)"RW";
			break;
		case PF_R | PF_X:
			flag_name = (char *)"RE";
			break;
		default:
			break;
		}


		printf("%-5d %-20s %-8.6X %-8.8X %-8.8X %-8.6X%-8.6X %-8s %-8.6X\n", phnum,
			type_name, phdr[phnum].p_offset, phdr[phnum].p_vaddr,
			phdr[phnum].p_paddr, phdr[phnum].p_filesz,
			phdr[phnum].p_memsz, flag_name, phdr[phnum].p_align);
	}
	printf("\nSection to Segment mapping:\n\n");

	for (int phnum = 0; phnum < elf_head.e_phnum; phnum++) {
		printf("%-5d", phnum);
		//段表末尾
		Elf32_Off segment_end = phdr[phnum].p_vaddr + phdr[phnum].p_memsz;
		//遍历节表查看位置是否重叠
		for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
			//得到节表的末尾位置
			Elf32_Off section_end = shdr[shnum].sh_addr + shdr[shnum].sh_size;

			//查看节表的位置是否和段的内存位置重叠
			if ((shdr[shnum].sh_addr >= phdr[phnum].p_vaddr && shdr[shnum].sh_addr <= segment_end) &&
				(section_end >= phdr[phnum].p_vaddr && section_end <= segment_end)) {
				//打印节名称
				printf("%s ", shstrtab + shdr[shnum].sh_name);
			}
		}
		printf("\n");
	}

	free(phdr);
	free(shstrtab);
	free(shdr);
}

//解析.dynsym符号表
void dynsym_table(FILE * fp) {
	//得到ELF文件头
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	//得到节表数组
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		return;
	}

	//得到.strtab
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		free(shdr);
		return;
	}
	char *temp = shstrtab;
	//找到.dynstr表
	char * dynstr = NULL;
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name字符串表的偏移
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynstr"))
		{
			dynstr = get_strtab(fp, shdr[shnum]);
			if (!dynstr) {
				free(shdr);
				free(shstrtab);
				return;
			}
			break;
		}
	}
	//遍历节表
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name字符串表的偏移
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynsym") || !strcmp(temp, ".symtab"))
		{
			int dynsym_num = shdr[shnum].sh_size / shdr[shnum].sh_entsize;
			printf("符号表'.dynsym'包含%d个条目\n\n", dynsym_num);
			if (fp_move(fp, shdr[shnum].sh_offset)) {
				exit(0);
			}
			print_dynsym_table_entry(fp, dynstr, dynsym_num);
		}
	}

	free(dynstr);
	free(shstrtab);
	free(shdr);
}

//解析节表
void section_header(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	printf("共有 %d 个节头, 节头表开始文件偏移为 0x%02x:\n", elf_head.e_shnum, elf_head.e_shoff);
	//这是一个Elf32_Shdr数组
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//得到字符串表信息
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}
	char *temp = shstrtab;

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
		case SHF_WRITE | SHF_ALLOC:
			flags = (char *)"WA";
			break;
		case SHF_EXECINSTR | SHF_ALLOC:
			flags = (char *)"AX";
			break;
		case SHF_MASKPROC:
			flags = (char *)"MS";
			break;
		case SHF_LINK_ORDER | SHF_ALLOC:
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
	free(shstrtab);
	free(shdr);
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

/*
	得到符号表
	释放内存
*/
Elf32_Sym * get_symtab(FILE * fp, Elf32_Shdr shdr) {
	//定位位置
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}
	//开辟内存
	Elf32_Sym *psym = (Elf32_Sym*)malloc(sizeof(Elf32_Sym) *(shdr.sh_size / shdr.sh_entsize));
	memset(psym, 0, sizeof(Elf32_Sym) *(shdr.sh_size / shdr.sh_entsize));
	if (psym == NULL) {
		printf("psym malloc failed\n");
		return 0;
	}
	//读取符号表
	int result;
	result = fread(psym, sizeof(Elf32_Sym), (shdr.sh_size / shdr.sh_entsize), fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(psym);
		return NULL;
	}
	return psym;
}