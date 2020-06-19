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

//�õ��ַ��������е�index���ַ���
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
	�õ�ELF�ڱ�����
	���ͷ��ڴ�
*/
Elf32_Shdr * get_elf_shdr(FILE * fp, Elf32_Ehdr elf_head) {
	//Elf32_Shdr������ÿ���ڱ�Ľṹ�壬��ͨ��Elf64_Shdr��С*elf_head.e_shnum�ڱ������õ�Ҫ������ڴ�
	Elf32_Shdr *shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * elf_head.e_shnum);
	memset(shdr, 0, sizeof(Elf32_Shdr) * elf_head.e_shnum);

	if (shdr == NULL) {
		printf("shdr malloc failed\n");
		return NULL;
	}

	int result = 0;
	//�ƶ�fpλ��
	result = fseek(fp, elf_head.e_shoff, SEEK_SET);
	if (result != 0) {
		printf("shdr fseek ERROR\n");
		free(shdr);
		return NULL;
	}
	//��ȡ����
	result = fread(shdr, sizeof(Elf32_Shdr), elf_head.e_shnum, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(shdr);
		return NULL;
	}
	return shdr;
}


/*
	�õ�ELF�α�����
	���ͷ��ڴ�
*/
Elf32_Phdr * get_elf_phdr(FILE * fp, Elf32_Ehdr elf_head) {
	//Elf32_Shdr������ÿ���ڱ�Ľṹ�壬��ͨ��Elf64_Shdr��С*elf_head.e_shnum�ڱ������õ�Ҫ������ڴ�
	Elf32_Phdr *phdr = (Elf32_Phdr*)malloc(sizeof(Elf32_Phdr) * elf_head.e_phnum);
	memset(phdr, 0, sizeof(Elf32_Phdr) * elf_head.e_phnum);

	if (phdr == NULL) {
		printf("phdr malloc failed\n");
		return NULL;
	}

	int result = 0;
	//�ƶ�fpλ��
	result = fseek(fp, elf_head.e_phoff, SEEK_SET);
	if (result != 0) {
		printf("phdr fseek ERROR\n");
		free(phdr);
		return NULL;
	}
	//��ȡ����
	result = fread(phdr, sizeof(Elf32_Phdr), elf_head.e_phnum, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(phdr);
		return NULL;
	}
	return phdr;
}

/*
	���ض�λ������
	���ͷ��ڴ�
	shdr һ���������� SHT_RELA����SHT_REL
*/
Elf32_Rel * get_reltab(FILE * fp, Elf32_Shdr shdr) {
	//��λ���ض�λ��λ��
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}

	//�õ��ض�λ��ĳ��ȣ��ֽ�����
	int sh_size = shdr.sh_size;
	//char shstrtab[i];
	//���������ض�λ��Ĵ�С
	Elf32_Rel *shreltab = (Elf32_Rel*)malloc(sizeof(Elf32_Rel) * sh_size);
	memset(shreltab, 0, sizeof(char) * sh_size);

	if (shreltab == NULL) {
		printf("�����ڴ� shreltab ERROR \n");
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
	�õ�.shstrtab��.dynstr���ַ���
	���ͷ��ڴ�
	shdr һ����.dynstr����.shstrtab
*/
char * get_strtab(FILE * fp, Elf32_Shdr shdr) {

	//��λ���ַ�����λ��
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}

	//�õ��ַ����ڱ�ĳ��ȣ��ֽ�����
	int sh_size = shdr.sh_size;
	//char shstrtab[i];
	//���������ַ��������Ĵ�С
	char *shstrtab = (char*)malloc(sizeof(char) * sh_size);
	memset(shstrtab, 0, sizeof(char) * sh_size);

	if (shstrtab == NULL) {
		printf("�����ڴ� str ERROR \n");
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


//�ƶ�fp  ʧ�ܷ���0
int fp_move(FILE * fp, int offset) {
	rewind(fp);
	int result;

	result = fseek(fp, offset, SEEK_SET);
	if (result != 0) {
		printf("fp_move ERROR \n");
		return 0;
	}
}

//��ӡ���ű���
int print_dynsym_table_entry(FILE * fp, char *dynstr, int dynsym_num) {

	//�����ڴ�
	Elf32_Sym *psym = (Elf32_Sym*)malloc(sizeof(Elf32_Sym) *dynsym_num);
	memset(psym, 0, sizeof(Elf32_Sym) *dynsym_num);
	if (psym == NULL) {
		printf("psym malloc failed\n");
		return 0;
	}
	//��ȡ���ű�
	int result;
	result = fread(psym, sizeof(Elf32_Sym), dynsym_num, fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(psym);
		return 0;
	}

	printf("%-5s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "Num", "Value", "��С", "����", "������", "Vis", "Ndx", "����");
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

//�����ض�λ��
void rel_table(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	//����һ���α�����
	Elf32_Phdr *phdr = get_elf_phdr(fp, elf_head);
	if (!phdr) {
		exit(0);
	}
	//����һ��Elf32_Shdr����
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//�õ��ַ�������Ϣ
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}

	//�õ������ַ�������Ϣ
	//�ҵ�.dynstr��
	char * dynstr = NULL;
	char * temp = shstrtab;
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name�ַ������ƫ��
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

	//�õ����ű���Ϣ
	Elf32_Sym * symtab = NULL;

	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name�ַ������ƫ��
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynsym"))
		{
			symtab= get_symtab(fp, shdr[shnum]);
		}
	}

	//ѭ���ҵ��ض�λ��
	for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
		if (shdr[shnum].sh_type == SHT_REL) {
			//�ض�λ���С
			int rel_num = shdr[shnum].sh_size / shdr[shnum].sh_entsize;
			printf(" �ض�λ��'%s' ��ʼλ��:0x%X ����%d���ض�λ�� \n", shstrtab + shdr[shnum].sh_name, shdr[shnum].sh_addr, rel_num);
			printf("%-10s %-10s %-15s %-10s %-10s\n", "�ض�λ��ַ", "�ض�λ��Ϣ", "�ض�λ����", "����ֵ", "��������");
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

//������ͷ��
void program_table(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	printf("���� %d ����ͷ, ��ͷ��ʼ�ļ�ƫ��Ϊ 0x%02x:\n\n", elf_head.e_phnum, elf_head.e_phoff);
	//����һ���α�����
	Elf32_Phdr *phdr = get_elf_phdr(fp, elf_head);
	if (!phdr) {
		exit(0);
	}
	//����һ��Elf32_Shdr����
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//�õ��ַ�������Ϣ
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}
	char *temp = shstrtab;

	printf("\n����Program����Ϣ:\n");
	printf("%-5s %-20s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
		"", "����", "�ļ�ƫ��", "�ڴ��ַ", "�����ַ", "�ļ���С", "�ڴ��С", "��־", "����");
	for (int phnum = 0; phnum < elf_head.e_phnum; phnum++) {

		char * type_name = (char *)"";
		switch (phdr[phnum].p_type)
		{
		case PT_NULL:
			type_name = (char *)"NULL(�ն�)";
			break;
		case PT_LOAD:
			type_name = (char *)"LOAD(��װ��)";
			break;
		case PT_DYNAMIC:
			type_name = (char *)"DYNAMIC(��̬������Ϣ)";
		case PT_INTERP:
			type_name = (char *)"INTERP(��̬���ӽ���)";
			break;
		case PT_NOTE:
			type_name = (char *)"NOTE(ר�еı�������Ϣ)";
			break;
		case PT_SHLIB:
			type_name = (char *)"SHLIB(�����)";
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
		//�α�ĩβ
		Elf32_Off segment_end = phdr[phnum].p_vaddr + phdr[phnum].p_memsz;
		//�����ڱ�鿴λ���Ƿ��ص�
		for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
			//�õ��ڱ��ĩβλ��
			Elf32_Off section_end = shdr[shnum].sh_addr + shdr[shnum].sh_size;

			//�鿴�ڱ��λ���Ƿ�Ͷε��ڴ�λ���ص�
			if ((shdr[shnum].sh_addr >= phdr[phnum].p_vaddr && shdr[shnum].sh_addr <= segment_end) &&
				(section_end >= phdr[phnum].p_vaddr && section_end <= segment_end)) {
				//��ӡ������
				printf("%s ", shstrtab + shdr[shnum].sh_name);
			}
		}
		printf("\n");
	}

	free(phdr);
	free(shstrtab);
	free(shdr);
}

//����.dynsym���ű�
void dynsym_table(FILE * fp) {
	//�õ�ELF�ļ�ͷ
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	//�õ��ڱ�����
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		return;
	}

	//�õ�.strtab
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		free(shdr);
		return;
	}
	char *temp = shstrtab;
	//�ҵ�.dynstr��
	char * dynstr = NULL;
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name�ַ������ƫ��
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
	//�����ڱ�
	for (int shnum = 0; shnum < elf_head.e_shnum; ++shnum) {
		temp = shstrtab;
		//shdr[shnum].sh_name�ַ������ƫ��
		temp = temp + shdr[shnum].sh_name;
		if (!strcmp(temp, ".dynsym") || !strcmp(temp, ".symtab"))
		{
			int dynsym_num = shdr[shnum].sh_size / shdr[shnum].sh_entsize;
			printf("���ű�'.dynsym'����%d����Ŀ\n\n", dynsym_num);
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

//�����ڱ�
void section_header(FILE * fp) {
	Elf32_Ehdr elf_head;
	fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	printf("���� %d ����ͷ, ��ͷ��ʼ�ļ�ƫ��Ϊ 0x%02x:\n", elf_head.e_shnum, elf_head.e_shoff);
	//����һ��Elf32_Shdr����
	Elf32_Shdr *shdr = get_elf_shdr(fp, elf_head);
	if (!shdr) {
		exit(0);
	}
	//�õ��ַ�������Ϣ
	char *shstrtab = get_strtab(fp, shdr[elf_head.e_shstrndx]);
	if (!shstrtab) {
		exit(0);
	}
	char *temp = shstrtab;

	printf("\n����section����Ϣ:\n\n");
	printf("%-5s %-22s %-23s %-8s %-8s %-7s %-3s %-3s %-3s %-3s %-3s\n", "����", "����", "����", "�ڴ��ַ", "�ļ�ƫ��", "��С", "ES", "��־", "����", "������Ϣ", "����");
	for (int shnum = 0; shnum < elf_head.e_shnum; shnum++) {
		temp = shstrtab;
		//shdr[shnum].sh_name�ַ������ƫ��
		temp = temp + shdr[shnum].sh_name;
		char *type_name = NULL;
		int has_free = 0;

		switch (shdr[shnum].sh_type)
		{
		case SHT_NULL:
			type_name = (char *)"NULL(������)";
			break;
		case SHT_PROGBITS:
			type_name = (char *)"PROGBITS(��������Ϣ)";
			break;
		case SHT_SYMTAB:
			type_name = (char *)"SYMTAB(���ű�)";
			break;
		case SHT_STRTAB:
			type_name = (char *)"STRTAB(�ַ�����)";
			break;
		case SHT_RELA:
			type_name = (char *)"RELA(�ض�λ����)";
			break;
		case SHT_HASH:
			type_name = (char *)"HASH(���Ź�ϣ��)";
			break;
		case SHT_DYNAMIC:
			type_name = (char *)"DYNAMIC(��̬������Ϣ)";
			break;
		case SHT_NOTE:
			type_name = (char *)"NOTE(����ļ���Ϣ)";
			break;
		case SHT_NOBITS:
			type_name = (char *)"NOBITS(��ռ���ļ��ռ�)";
			break;
		case SHT_REL:
			type_name = (char *)"REL(�ض�λ����)";
			break;
		case SHT_SHLIB:
			type_name = (char *)"SHLIB(�˽���������)";
			break;
		case SHT_DYNSYM:
			type_name = (char *)"DYNSYM(�������ű�)";
			break;
		default:
			type_name = my_strupr(temp);
			has_free = 1;
			break;
		}
		//��־����
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

//��ӡELFͷ����Ϣ
void file_header(FILE * fp) {
	printf("ELF Header:\n");
	Elf32_Ehdr elf_head;

	int a;

	a = fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
	if (a != 0) {
		//�ж��Ƿ���ELFħ��
		if (elf_head.e_ident[EI_MAG0] != 0x7f && elf_head.e_ident[EI_MAG1] != 'E'
			&& elf_head.e_ident[EI_MAG2] != 'L' && elf_head.e_ident[EI_MAG3] != 'F') {
			printf("target is not ELF!\n");
			exit(0);
		}
		//��ӡMagicֵ
		printf(" %-53s %02X %-22.02X ELF \n", "Magic(ħ����ʶ):",
			elf_head.e_ident[EI_MAG0], elf_head.e_ident[EI_MAG1], elf_head.e_ident[EI_MAG2], elf_head.e_ident[EI_MAG3]);
		//Ŀ���ļ�������Ŀ����������
		switch (elf_head.e_ident[EI_CLASS])
		{
		case ELFCLASSNONE:
			printf(" %-53s %-25.02X ELFCLASSNONE(�Ƿ����)\n", "Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
			break;
		case ELFCLASS32:
			printf(" %-53s %-25.02X ELFCLASS32(32λĿ��)\n", "Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
			break;
		case ELFCLASS64:
			printf(" %-53s %-25.02X ELFCLASS64(64λĿ��)\n", "Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
			break;
		default:
			break;
		}

		//���ݱ��뷽ʽ
		switch (elf_head.e_ident[EI_CLASS])
		{
		case ELFDATANONE:
			printf(" %-53s %-25.02X ELFDATANONE(�Ƿ����ݱ���)\n", "Data(���ݱ��뷽ʽ):", elf_head.e_ident[EI_DATA]);
			break;
		case ELFDATA2LSB:
			printf(" %-53s %-25.02X ELFDATA2LSB(С��)\n", "Data(���ݱ��뷽ʽ):", elf_head.e_ident[EI_DATA]);
			break;
		case ELFDATA2MSB:
			printf(" %-53s %-25.02X ELFDATA2MSB(���)\n", "Data(���ݱ��뷽ʽ):", elf_head.e_ident[EI_DATA]);
			break;
		default:
			break;
		}

		//����ֵû���õ�����Ӳ����
		printf(" %-53s %-25.02X %s\n", "Version:", elf_head.e_ident[EI_VERSION], "1 (current)");
		printf(" %-53s %s\n", "OS/ABI:", "UNIX - System V");
		printf(" %-53s %s\n", "ABI Version:", "0");

		//elf�ļ�������
		if (elf_head.e_type == ET_NONE) {
			printf(" %-53s %-25.02X ET_NONE(δ֪Ŀ���ļ���ʽ)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_REL) {
			printf(" %-53s %-25.02X ET_REL(���ض�λ�ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_EXEC) {
			printf(" %-53s %-25.02X ET_EXEC(��ִ���ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_DYN) {
			printf(" %-53s %-25.02X ET_DYN(����Ŀ���ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_CORE) {
			printf(" %-53s %-25.02X ET_CORE(Core �ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_LOPROC) {
			printf(" %-53s %-25.02X ET_LOPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type == ET_HIPROC) {
			printf(" %-53s %-25.02X ET_HIPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}
		else if (elf_head.e_type > 0xff00 && elf_head.e_type < 0xffff) {
			printf(" %-53s %-25.02X ET_LOPROC~ET_HIPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
		}

		//Ŀ����ϵ�ṹ��������e_machine̫������ֻ��������
		switch (elf_head.e_machine)
		{
		case EM_NONE:
			printf(" %-53s %-25.02X EM_NONE(δָ��)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_M32:
			printf(" %-53s %-25.02X EM_M32(AT&T WE 32100)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_SPARC:
			printf(" %-53s %-25.02X EM_SPARC(SPARC)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_386:
			printf(" %-53s %-25.02X EM_386(Intel 80386)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_68K:
			printf(" %-53s %-25.02X EM_68K(Motorola 68000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_88K:
			printf(" %-53s %-25.02X EM_88K(Motorola 88000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_860:
			printf(" %-53s %-25.02X EM_860(Intel 80860)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_MIPS:
			printf(" %-53s %-25.02X EM_MIPS(MIPS RS3000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_ARM:
			printf(" %-53s %-25.02X EM_ARM(ARM)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		case EM_X86_64:
			printf(" %-53s %-25.02X EM_X86_64(64)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		default:
			printf(" %-53s %-25.02X others(Ԥ��)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
			break;
		}

		printf(" %-53s %-25.02X %s\n", "Version:", elf_head.e_ident[EI_VERSION], "1");
		printf("\n");
		//e_entry������ڵ�ַ,��ִ���ļ���e_entryָ��C���е�_start������̬��.so�еĽ����ָ�� call_gmon_start
		//��Ϊ��̬���ӿ⣬e_entry��ڵ�ַ��������ģ���Ϊ���򱻼���ʱ���趨����ת��ַ�Ƕ�̬�������ĵ�ַ������ֶ��ǿ��Ա���Ϊ�������ġ�
		printf(" %-53s 0x%x\n", "Entry point address(������ڵ�ַ):", elf_head.e_entry);

		printf(" %-53s %d (bytes into file) \n", "Start of program headers(����ͷ����ƫ�Ƶ�ַ):", elf_head.e_phoff);
		printf(" %-53s %d (bytes into file) \n", "Start of section headers(����ͷ����ƫ�Ƶ�ַ):", elf_head.e_shoff);
		printf(" %-53s 0x%-25.02X \n", "Flags(�������ı�־):", elf_head.e_flags);
		printf(" %-53s %d (bytes) \n", "Size of this header(ELFͷ�Ĵ�С):", elf_head.e_ehsize);
		printf(" %-53s %d (bytes) \n", "Size of program headers(ÿ������ͷ����Ĵ�С):", elf_head.e_phentsize);
		printf(" %-53s %d \n", "Number of program headers(����ͷ���������):", elf_head.e_phnum);
		printf(" %-53s %d (bytes) \n", "Size of section headers(ÿ������ͷ����Ĵ�С):", elf_head.e_shentsize);
		printf(" %-53s %d \n", "Number of section headers(����ͷ���������):", elf_head.e_shnum);
		printf(" %-53s %d \n", "Section header string table index(�����ַ�����λ��):", elf_head.e_shstrndx);
	}
	else {
		printf("READ ERROR\n");
		exit(0);
	}
}

//��ӡ������Ϣ
void help()
{
	printf("����Shark Chilli�Ľ�����0.0,�����ʿ��Է��͵��ҵ�����:1243596620@qq.com\n");
	printf("-h            :ͷ����Ϣ\n");
	printf("-S            :��������Ϣ\n");
	printf("-s            :���ű���Ϣ\n");
	printf("-l            :����ͷ��Ϣ\n");
	printf("-r            :�ض�λ����Ϣ\n");
}


//�ַ�����д
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
	�õ����ű�
	�ͷ��ڴ�
*/
Elf32_Sym * get_symtab(FILE * fp, Elf32_Shdr shdr) {
	//��λλ��
	if (fp_move(fp, shdr.sh_offset)) {
		return NULL;
	}
	//�����ڴ�
	Elf32_Sym *psym = (Elf32_Sym*)malloc(sizeof(Elf32_Sym) *(shdr.sh_size / shdr.sh_entsize));
	memset(psym, 0, sizeof(Elf32_Sym) *(shdr.sh_size / shdr.sh_entsize));
	if (psym == NULL) {
		printf("psym malloc failed\n");
		return 0;
	}
	//��ȡ���ű�
	int result;
	result = fread(psym, sizeof(Elf32_Sym), (shdr.sh_size / shdr.sh_entsize), fp);
	if (result == 0) {
		printf("READ ERROR\n");
		free(psym);
		return NULL;
	}
	return psym;
}