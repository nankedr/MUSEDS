#include <pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "hash.h"
#define bool int
#define true 1
#define false 0
#define MAX_CHAR 200
#define INDEXNUM 4000
#define FILENUM 5000

//第一项记录元素个数
size_t hashMap[7500][100];

float time_use=0;
struct timeval start, end;
char strLine[MAX_CHAR];
pairing_t pairing;
element_t g1;
element_t g2;
element_t pk_o, sk_o;
element_t pk_i, sk_i;
element_t pk_fs_1, pk_fs_2, sk_fs;
element_t pk_ss_1, pk_ss_2, sk_ss;
element_t tempG1;
element_t tempG2;
element_t tempGT;
element_t tempGT2;
element_t sk_o_inv, sk_i_inv;

element_t p;
element_t tempZr;

uint8_t sk_id[32]={0};//AES文档加密密钥256位

struct S_AI_o_i
{
    unsigned long long u_i;
    element_t ai;
}AI_o_i ;

typedef struct
{
    element_t T1;
    element_t T2;
    element_t T3;
}S_T_i_w;
typedef  struct
{
    element_t T1;
    element_t T2;
}S_T_fs_w;

struct S_Pri
{
    char w[30];
    uint8_t pt[28];
}Pri[INDEXNUM];

int Pri_idx = 0;//指示当前Pri的下一个空位置

struct S_C
{
    uint8_t C1[28];
    element_t C2;
    uint8_t C3[64];

}C[INDEXNUM*FILENUM/2];
int C_idx = 0;//指示当前密文索引C的下一个空位置

int hashFun(uint8_t *L, size_t n)
{
    int sum = 0;
    for (int i=0; i<n; ++i)
    {
        sum += L[i];
    }
    return sum;
}

/*
*{L:idx,...}
*
*/
void setHashMap(uint8_t *L, size_t n, size_t idx)
{
    int hashValue = hashFun(L, n);
    hashMap[hashValue][++hashMap[hashValue][0]] = idx;
}


void keyGen()
{
    //参数配置
    char param[1024];
    //FILE* f = fopen("a.param", "r");
    FILE* f = fopen("d159.param", "r");
    size_t count = fread(param, 1, 1024, f);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_Zr(sk_o, pairing);
    element_init_Zr(sk_i, pairing);
    element_init_Zr(sk_fs, pairing);
    element_init_Zr(sk_ss, pairing);

    element_init_G2(pk_o, pairing);
    element_init_G2(pk_i, pairing);
    element_init_G1(pk_fs_1, pairing);
    element_init_G2(pk_fs_2, pairing);
    element_init_G1(pk_ss_1, pairing);
    element_init_G2(pk_ss_2, pairing);

    element_init_G1(tempG1, pairing);
    element_init_G2(tempG2, pairing);

    element_init_GT(tempGT, pairing);
    element_init_GT(tempGT2, pairing);

    element_init_Zr(sk_o_inv, pairing);
    element_init_Zr(sk_i_inv, pairing);
    element_init_Zr(tempZr, pairing);


    element_init_Zr(p, pairing);

    element_random(g1);
    element_random(g2);
    //element_printf("g = %B\n", g);
    element_random(p);
    //element_printf("p = %B\n", p);

    element_random(sk_o);
    element_random(sk_i);
    element_random(sk_fs);
    element_random(sk_ss);

    element_invert(sk_o_inv, sk_o);
    element_invert(sk_i_inv, sk_i);

    element_pow_zn(pk_o, g2, sk_o_inv);
    element_pow_zn(pk_i, g2, sk_i_inv);
    element_pow_zn(pk_fs_1, g1, sk_fs);
    element_pow_zn(pk_fs_2, g2, sk_fs);
    element_pow_zn(pk_ss_1, g1, sk_ss);
    element_pow_zn(pk_ss_2, g2, sk_ss);

}
void auth()
{
    element_init_G2(AI_o_i.ai, pairing);
    element_div(tempZr, p, sk_o);
    element_pow_zn(AI_o_i.ai, pk_i, tempZr);
    AI_o_i.u_i = 100;
}

void trapGen(S_T_i_w* ptr_T_i_w, const char* w)
{
    uint8_t digest[32];
    element_t r1, r2;//用户生成r1,r2
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_random(r1);
    element_random(r2);
    element_init_G1(ptr_T_i_w->T1, pairing);
    element_init_G1(ptr_T_i_w->T2, pairing);
    element_init_G1(ptr_T_i_w->T3, pairing);

    element_pow_zn(ptr_T_i_w->T1, pk_ss_1, r1);
    element_pow_zn(ptr_T_i_w->T2, pk_fs_1, r2);


    H_1(digest, w, strlen(w));
    element_add(tempZr, r1, r2);
    element_from_hash(tempG1, digest, 32);
    element_pow2_zn(ptr_T_i_w->T3, tempG1, sk_i, g1, tempZr);

    element_clear(r1);
    element_clear(r2);

}

void frontTrap(S_T_fs_w* ptr_T_fs_w, S_T_i_w* ptr_T_i_w)
{
    element_init_G1(ptr_T_fs_w->T1, pairing);
    element_set(ptr_T_fs_w->T1, ptr_T_i_w->T1);
    element_init_GT(ptr_T_fs_w->T2, pairing);
    element_invert(tempZr, sk_fs);
    element_pow_zn(tempG1, ptr_T_i_w->T2, tempZr);
    element_div(tempG1, ptr_T_i_w->T3, tempG1);
    element_pairing(ptr_T_fs_w->T2, tempG1, AI_o_i.ai);
}

void xor(uint8_t *dest, uint8_t *src, size_t n)
{
    int i;
    for (i=0; i < n; ++i)
    {
        dest[i] ^=src[i];
    }
}

void random_gen_L(uint8_t * L, size_t n)
{
    while(1)
    {
        int ret=RAND_status();  /*检测熵值*/
        if(ret==1)
        {
            break;
        }
        else
        {
            RAND_poll();
        }
    }

    RAND_bytes(L, n);
}
/*
*索引建立
*参数w 索引词
*参数id 文档标示（先采用32位）
*
*/
void indexEnc(const char* w, uint32_t id)
{
    int w_idx = -1;
    uint8_t L[28];
    uint8_t digest[32];
    uint8_t digestH2[28];
    uint8_t digestH3[64];
    uint8_t tempbuff[64];
    uint8_t* buff;
    int n;

    random_gen_L(L, sizeof(L));//随机生成192位L,自己实现

    element_random(tempZr);
    element_init_G1(C[C_idx].C2, pairing);
    element_pow_zn(C[C_idx].C2, g1, tempZr);//C2=g^r

    for(int i=0; i<Pri_idx; ++i)//顺序遍历判断索引词是否存在
    {
        if(!strcmp(Pri[i].w, w))
        {
            w_idx = i;
            break;
        }
    }

    if(w_idx == -1)//索引词不存在
    {
        strncpy(Pri[Pri_idx].w, w, strlen(w));
        memcpy(Pri[Pri_idx++].pt, L, sizeof(L));

        H_1(digest, w, strlen(w));
        element_from_hash(tempG1, digest, 32);
        element_pow_zn(tempG1, tempG1, p);//temp=H1(w)^p

        element_pairing(tempGT, tempG1, pk_ss_2);
        element_pow_zn(tempGT, tempGT, sk_o_inv);

        buff = (uint8_t*)calloc(element_length_in_bytes(tempGT), sizeof(uint8_t));
        n = element_to_bytes(buff, tempGT);
        H_2(digestH2, buff, n);
        memcpy(C[C_idx].C1, digestH2, sizeof(digestH2));
        free(buff);
    }
    else//索引词存在
    {
        memcpy(C[C_idx].C1, Pri[w_idx].pt, sizeof(Pri[w_idx].pt));
        memcpy(Pri[w_idx].pt, L, sizeof(L));
    }

    //计算C3
    element_mul(tempZr, p, tempZr);
    element_pow_zn(tempG1, g1, tempZr);
    element_pairing(tempGT, tempG1, pk_ss_2);
    element_pow_zn(tempGT, tempGT, sk_o_inv);
    buff = (uint8_t*)calloc(element_length_in_bytes(tempGT), sizeof(uint8_t));
    n = element_to_bytes(buff, tempGT);
    H_3(digestH3, buff, n);

    free(buff);

    memcpy(tempbuff, &id, sizeof(id));//4字节
    memcpy(tempbuff+4, L, sizeof(L));//28字节
    memcpy(tempbuff+4+28, sk_id, sizeof(sk_id));
    xor(digestH3, tempbuff, sizeof(digestH3));

    //C3赋值
    memcpy(C[C_idx++].C3, digestH3, sizeof(digestH3));

}

int serch_L_exist(uint8_t *L, size_t n)
{

     int idx, i;
    int hashValue = hashFun(L, n);
    size_t next_idx = hashMap[hashValue][0];

    if (next_idx == 1)
        return hashMap[hashValue][next_idx];

    for (i=1; i<=next_idx; ++i)
    {
        idx = hashMap[hashValue][i];
        if (!memcmp(L, C[idx].C1, n))
            return idx;
    }
    return -1;
    /*

    for (int i=0; i<C_idx; ++i)
    {
        if (!memcmp(L, C[i].C1, n))
            return i;
    }
    return -1;
    */
}
void print_bin(const char* label, uint8_t* msg, size_t n, const char* label2)
{
    printf("%s", label);
    for (int i=0; i<n; ++i)
    {
        printf("%02x", msg[i]);
    }
    printf("%s", label2);
}
int search(S_T_fs_w* ptr_T_fs_w)
{
    uint8_t L[28];
    uint8_t digestH3[64];
    uint8_t *buff;
    int n;
    int idx = -1;
	int result_num = 0;
    element_pow_zn(tempGT, ptr_T_fs_w->T2, sk_ss);
    element_pairing(tempGT2, ptr_T_fs_w->T1, AI_o_i.ai);
    element_div(tempGT, tempGT, tempGT2);

    buff = (uint8_t*)calloc(element_length_in_bytes(tempGT), sizeof(uint8_t));
    n = element_to_bytes(buff, tempGT);
    H_2(L, buff, n);
    free(buff);
    while (true)
    {
        idx = serch_L_exist(L, sizeof(L));

        if (idx != -1)//搜索C1==L
        {
            element_pairing(tempGT, C[idx].C2, AI_o_i.ai);//U1
            element_pow_zn(tempGT, tempGT, sk_ss);
            //U2=C3
            //下面是用户过程计算（id||pt||sk_id) = H_3(U1^sk_i)xorU2
            element_pow_zn(tempGT2, tempGT, sk_i);

            buff = (uint8_t*)calloc(element_length_in_bytes(tempGT2), sizeof(uint8_t));
            n = element_to_bytes(buff, tempGT2);

            H_3(digestH3, buff, n);
            xor(digestH3, C[idx].C3, sizeof(digestH3));

			++result_num;

            printf("id: %d\n", *(uint32_t*)digestH3);
            /*
            print_bin("(", digestH3, 4, ")\n");
            print_bin("sk_id: ", digestH3+32, 32, "\n");
            */

            //计算出Pt是还要返回给SS
            memcpy(L, digestH3+4, 28);
            idx = -1;
        }
        else
        {
            printf("end\n");
            return result_num;
        }
    }
}
void clear()
{
    element_clear(g1);
    element_clear(g2);
    element_clear(p);
    element_clear(pk_o);
    element_clear(sk_o);
    element_clear(pk_i);
    element_clear(sk_i);
    element_clear(pk_fs_1);
    element_clear(pk_fs_2);
    element_clear(sk_fs);
    element_clear(pk_ss_1);
    element_clear(pk_ss_2);
    element_clear(sk_ss);
    element_clear(tempG1);
    element_clear(tempG2);
    element_clear(tempGT);
    element_clear(tempGT2);
    element_clear(sk_o_inv);
    element_clear(sk_i_inv);
    element_clear(p);
    element_clear(tempZr) ;
}

void interact_search()
{
    S_T_i_w* ptr_T_i_w = (S_T_i_w*)malloc(sizeof(S_T_i_w));
    S_T_fs_w* ptr_T_fs_w = (S_T_fs_w*)malloc(sizeof(S_T_fs_w));
    char input[50];
	int n;

    while (true)
    {
        fgets(input, 50, stdin);
        input[strlen(input)-1] = '\0';
        if (!strncmp(input, "quit", 4))
        {
            return ;
        }
		gettimeofday(&start, NULL);
        trapGen(ptr_T_i_w, input);
        frontTrap(ptr_T_fs_w, ptr_T_i_w);
        n = search(ptr_T_fs_w);
		gettimeofday(&end, NULL);

	    time_use = (end.tv_sec-start.tv_sec)*1000000 + (end.tv_usec-start.tv_usec);//微秒
        printf("time_use:%f, result_doc:%d\n", time_use/1e6, n);

        element_clear(ptr_T_i_w->T1);
        element_clear(ptr_T_i_w->T2);
        element_clear(ptr_T_i_w->T3);
        element_clear(ptr_T_fs_w->T1);
        element_clear(ptr_T_fs_w->T2);
    }

    free(ptr_T_i_w);
    free(ptr_T_fs_w);

}

int read_index()
{
    FILE* fp;
    char* s;
    uint32_t doc_id;
    int doc_num = 0;

    if ((fp=fopen("index_test", "r")) == NULL)
    {
        printf("no index file!\n");
        exit(-1);
    }
    while (!feof(fp))
    {
        fgets(strLine, MAX_CHAR, fp);
        if (feof(fp))
            break;
        strLine[strlen(strLine)-1] = '\0';
        s = strtok(strLine, " ");
        if (!s)
            break;
        doc_id = atoi(s);
        ++doc_num;

        while (true)
        {
            s = strtok(NULL, " ");
            if (!s)
                break;
            //printf("%s\n", s);
            indexEnc(s, doc_id);
        }
        printf("index:%d\n", doc_id);
    }
    fclose(fp);
    return doc_num;
}
int main(int argc, char **argv)
{

    char buff[20]="我的随机数";
    RAND_add(buff, 20, strlen(buff));
    strcpy(buff, "23424d");
    RAND_seed(buff, 20);

    int doc_num = 0;
    int i;

	double index_mem_use = 0;
	double user_auth_mem_use = 0;

    keyGen();
    auth();
/*
    test_indexEnc();
    test_search();
*/
	gettimeofday(&start, NULL);
    doc_num = read_index();
	gettimeofday(&end, NULL);
	time_use = (end.tv_sec-start.tv_sec)*1000000 + (end.tv_usec-start.tv_usec);//微秒
	printf("index construction: %f\n", time_use/1e6);
	printf("document:%d\n", doc_num);
	printf("Pri:%d\n", Pri_idx);
    printf("C:%d\n", C_idx);
	index_mem_use = (sizeof(struct S_C)+element_length_in_bytes(C[0].C2)) * C_idx / (double)(1024*1024);

	printf("index memory used:%fM\n", index_mem_use);
	
	user_auth_mem_use += (sizeof(AI_o_i) + element_length_in_bytes(AI_o_i.ai))*500;
	printf("500user_auth_mem_use:%f\n", user_auth_mem_use/1024/1024);

    for (i=0; i<C_idx; ++i)
    {
        setHashMap(C[i].C1, 28, i);
    }

    printf("index construction complete...\n");
    interact_search();
    //test_C1_equal_L();
    clear();
    return 0;
}




