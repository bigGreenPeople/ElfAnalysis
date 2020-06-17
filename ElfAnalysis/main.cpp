#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <malloc.h>

#include "elf.h"

void help();
void file_header(FILE * fp);
void section_header(FILE * fp);


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
	printf("���� %d ����ͷ, ��ͷ��ʼ�ļ�ƫ��Ϊ 0x%02x:\n", elf_head.e_shnum, elf_head.e_shoff);
	//Elf32_Shdr������ÿ���ڱ�Ľṹ�壬��ͨ��Elf64_Shdr��С*elf_head.e_shnum�ڱ������õ�Ҫ������ڴ�
	//����һ��Elf32_Shdr����
	Elf32_Shdr *shdr = (Elf32_Shdr*)malloc(sizeof(Elf32_Shdr) * elf_head.e_shnum);
	if (shdr == NULL) {
		printf("shdr malloc failed\n");
		exit(0);
	}
	int a = 0;
	//�ƶ�fpλ��
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
	//�����ļ�λ��Ϊ������ stream ���ļ��Ŀ�ͷ��
	rewind(fp);
	//��λ���ַ�����λ��
	a = fseek(fp, (long)shdr[elf_head.e_shstrndx].sh_offset, SEEK_SET);
	if (a != 0) {
		printf("��λ���ַ����ڱ�λ�� %d \n", shdr[elf_head.e_shstrndx].sh_offset);
		printf("��λ���ַ����ڱ�λ�� shstrtab fseek ERROR \n");
		exit(0);
	}
	//�õ��ַ����ڱ�ĳ��ȣ��ֽ�����
	int sh_size = shdr[elf_head.e_shstrndx].sh_size;
	//char shstrtab[i];
	//���������ַ��������Ĵ�С
	char *shstrtab = (char*)malloc(sizeof(char) * sh_size);
	char *temp = shstrtab;

	a = fread(shstrtab, sh_size, 1, fp);
	if (a == 0) {
		printf("READ ERROR\n");
		exit(0);
	}
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
