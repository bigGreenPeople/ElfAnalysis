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
int print_dynsym_table_entry(FILE * fp, char *dynstr, int dynsym_num);
int fp_move(FILE * fp, int offset);
char * my_strupr(char *str);
char * get_strtab(FILE * fp, Elf32_Shdr shdr);
Elf32_Shdr * get_elf_shdr(FILE * fp, Elf32_Ehdr elf_head);
Elf32_Phdr * get_elf_phdr(FILE * fp, Elf32_Ehdr elf_head);


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
			, sym_ndx, dynstr+ psym[dynsym_index].st_name);
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
		"","����", "�ļ�ƫ��", "�ڴ��ַ", "�����ַ", "�ļ���С", "�ڴ��С", "��־","����");
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
		case PF_W| PF_X:
			flag_name = (char *)"WE";
			break;
		case PF_R |PF_W:
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
			if ((shdr[shnum].sh_addr>= phdr[phnum].p_vaddr && shdr[shnum].sh_addr <= segment_end) && 
				(section_end >= phdr[phnum].p_vaddr && section_end <= segment_end)) {
				//��ӡ������
				printf("%s ",shstrtab+ shdr[shnum].sh_name);
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
	Elf32_Shdr *shdr = get_elf_shdr(fp,elf_head);
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
