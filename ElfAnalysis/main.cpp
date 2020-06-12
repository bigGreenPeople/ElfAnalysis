#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf.h"

void help();
void finleheader(const char * pbuff);

int main(int argc, char* argv[]) {
	if (argc < 3)
	{
		printf("invalid arguments\n");
		exit(0);
	}

	FILE *fp;
	errno_t err = 0;
	int shnum, a;

	/*printf("1: %s\n", argv[0]);
	printf("2: %s\n", argv[1]);
	printf("3: %s\n", argv[2]);*/
	err = fopen_s(&fp, argv[2], "r");
	if (NULL == fp)
	{
		printf("open file fail\n");
		exit(0);
	}
	printf("--------------------------------------------------------------------------------------------------\n");
	if (!strcmp(argv[1], "-h")) {
		printf("ELF Header:\n");
		Elf32_Ehdr elf_head;
		a = fread(&elf_head, sizeof(Elf32_Ehdr), 1, fp);
		if (a != 0) {
			//�ж��Ƿ���ELFħ��
			if (elf_head.e_ident[EI_MAG0] != 0x7f && elf_head.e_ident[EI_MAG1] != 'E'
				&& elf_head.e_ident[EI_MAG2] != 'L' && elf_head.e_ident[EI_MAG3] != 'F') {
				printf("target is not ELF!\n");
				exit(0);
			}
			//��ӡMagicֵ
			printf(" %-33s %02X %-22.02X ELF \n","Magic(ħ����ʶ):",
				elf_head.e_ident[EI_MAG0], elf_head.e_ident[EI_MAG1], elf_head.e_ident[EI_MAG2], elf_head.e_ident[EI_MAG3]);
			//Ŀ���ļ�������Ŀ����������
			switch (elf_head.e_ident[EI_CLASS])
			{
			case ELFCLASSNONE:
				printf(" %-33s %-25.02X ELFCLASSNONE(�Ƿ����)\n", "Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
				break;
			case ELFCLASS32:
				printf(" %-33s %-25.02X ELFCLASS32(32λĿ��)\n", "Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
				break;
			case ELFCLASS64:
				printf(" %-33s %-25.02X ELFCLASS64(64λĿ��)\n","Class(����ƽ̨):", elf_head.e_ident[EI_CLASS]);
				break;
			default:
				break;
			}
			//���ݱ��뷽ʽ
			switch (elf_head.e_ident[EI_CLASS])
			{
			case ELFDATANONE:
				printf(" %-33s %-25.02X ELFDATANONE(�Ƿ����ݱ���)\n", "Data(���ݱ��뷽ʽ):", elf_head.e_ident[EI_DATA]);
				break;
			case ELFDATA2LSB:
				printf(" %-33s %-25.02X ELFDATA2LSB(С��)\n", "Data(���ݱ��뷽ʽ):", elf_head.e_ident[EI_DATA]);
				break;
			case ELFDATA2MSB:
				printf(" %-33s %-25.02X ELFDATA2MSB(���)\n", "Data(���ݱ��뷽ʽ):",elf_head.e_ident[EI_DATA]);
				break;
			default:
				break;
			}

			//����ֵû���õ�����Ӳ����
			printf(" %-33s %-25.02X %s\n","Version:", elf_head.e_ident[EI_VERSION],"1 (current)");
			printf(" %-33s %s\n", "OS/ABI:", "UNIX - System V");
			printf(" %-33s %s\n", "ABI Version:", "0");

			//elf�ļ�������
			if (elf_head.e_type == ET_NONE) {
				printf(" %-33s %-25.02X ET_NONE(δ֪Ŀ���ļ���ʽ)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}else if (elf_head.e_type == ET_REL) {
				printf(" %-33s %-25.02X ET_REL(���ض�λ�ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type == ET_EXEC) {
				printf(" %-33s %-25.02X ET_EXEC(��ִ���ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type == ET_DYN) {
				printf(" %-33s %-25.02X ET_DYN(����Ŀ���ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type == ET_CORE) {
				printf(" %-33s %-25.02X ET_CORE(Core �ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type == ET_LOPROC) {
				printf(" %-33s %-25.02X ET_LOPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type == ET_HIPROC) {
				printf(" %-33s %-25.02X ET_HIPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}
			else if (elf_head.e_type > 0xff00 && elf_head.e_type < 0xffff) {
				printf(" %-33s %-25.02X ET_LOPROC~ET_HIPROC(�ض��������ļ�)\n", "Type(elf�ļ�����):", elf_head.e_type);
			}

			//Ŀ����ϵ�ṹ��������e_machine̫������ֻ��������
			switch (elf_head.e_machine)
			{
			case EM_NONE:
				printf(" %-33s %-25.02X EM_NONE(δָ��)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_M32:
				printf(" %-33s %-25.02X EM_M32(AT&T WE 32100)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_SPARC:
				printf(" %-33s %-25.02X EM_SPARC(SPARC)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_386:
				printf(" %-33s %-25.02X EM_386(Intel 80386)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_68K:
				printf(" %-33s %-25.02X EM_68K(Motorola 68000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_88K:
				printf(" %-33s %-25.02X EM_88K(Motorola 88000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_860:
				printf(" %-33s %-25.02X EM_860(Intel 80860)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_MIPS:
				printf(" %-33s %-25.02X EM_MIPS(MIPS RS3000)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_ARM:
				printf(" %-33s %-25.02X EM_ARM(ARM)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			case EM_X86_64:
				printf(" %-33s %-25.02X EM_X86_64(64)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			default:
				printf(" %-33s %-25.02X others(Ԥ��)\n", "Machine(Ŀ����ϵ�ṹ����):", elf_head.e_machine);
				break;
			}

			printf(" %-33s %-25.02X %s\n", "Version:", elf_head.e_ident[EI_VERSION], "1");

			//e_entry������ڵ�ַ,��ִ���ļ���e_entryָ��C���е�_start������̬��.so�еĽ����ָ�� call_gmon_start
			//��Ϊ��̬���ӿ⣬e_entry��ڵ�ַ��������ģ���Ϊ���򱻼���ʱ���趨����ת��ַ�Ƕ�̬�������ĵ�ַ������ֶ��ǿ��Ա���Ϊ�������ġ�
			printf(" %-33s %x\n", "Entry point address(������ڵ�ַ):", elf_head.e_entry);
		}
		else {
			printf("READ ERROR\n");
			exit(0);
		}
	}

	//help();

	if (fp) {
		err = fclose(fp);
		if (err == 0) {
			printf("--------------------------------------------------------------------------------------------------\n");
			//printf("The file closed\n");
		}
		else {
			printf("The file was not closed\n");
		}
	}
	return 0;
}

//��ӡELFͷ����Ϣ
void finleheader(const char * pbuff) {
	printf("ELF Header:\n");

	Elf32_Ehdr elf_head;

	//Magic
	printf("	Magic:	");
	for (int i = 0; i < EI_NIDENT; ++i) {
		printf("%02X", pbuff[i]);
		putchar(' ');
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