#include <pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "hash.h"
#define bool int
#define true 1
#define false 0
#define MAX_CHAR 200
#define WORDNUM 50
#define FILENUM 6000

float time_use=0;
struct timeval start, end;
char strLine[MAX_CHAR];
char words_array[WORDNUM][30];

pairing_t pairing;
element_t g1;
element_t g2;
element_t x_i, y_i, x_j,y_j, MPK_i, MPK_j;
element_t TK_i_j;

element_t tempG1;
element_t tempG2;
element_t tempG22;

element_t tempGT;
element_t tempGT2;

element_t p;
element_t tempZr;

element_t k1, k2;

struct S_C
{
    element_t c1;
    element_t c2;
};

struct S_Index_id//正排索引节点
{
    uint32_t id;
    struct S_C TAG_id[WORDNUM];
    uint32_t wordnum;
    element_t delta_id[2];
    uint32_t delta_id_num;
}Index_id[FILENUM];
size_t index_idx = 0;//下一个空白索引位置

void keyGen()
{
    //参数配置
    char param[1024];
    FILE* f = fopen("param/d159.param", "r");
    size_t count = fread(param, 1, 1024, f);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_Zr(x_i, pairing);
    element_init_Zr(y_i, pairing);
    element_init_Zr(x_j, pairing);
    element_init_Zr(y_j, pairing);

    element_init_G2(MPK_i, pairing);
    element_init_G2(MPK_j, pairing);
    element_init_G2(TK_i_j, pairing);

    element_init_G1(tempG1, pairing);
    element_init_G2(tempG2, pairing);
    element_init_G2(tempG22, pairing);

    element_init_GT(tempGT, pairing);
    element_init_GT(tempGT2, pairing);

    element_init_Zr(tempZr, pairing);


    element_init_Zr(p, pairing);

    element_init_Zr(k1, pairing);
    element_init_Zr(k2, pairing);

    element_random(g1);
    element_random(g2);
    //element_printf("g = %B\n", g);
    element_random(p);
    //element_printf("p = %B\n", p);
    element_random(x_i);
    element_random(y_i);
    element_random(x_j);
    element_random(y_j);

    element_random(k1);
    element_random(k2);

    element_pow_zn(MPK_i, g2, x_i);
    element_pow_zn(MPK_j, g2, x_j);


}
void follow()
{
    uint8_t *buff;
    int n;
    uint8_t digest[32];
    uint32_t i = 0;
    uint32_t j = 1;


    element_mul(tempZr, x_i, x_j);//tempZr = x_i*x_j
    element_pow_zn(tempG2, g2, tempZr);//tempG2=g2^(xi*xj)
    buff = (uint8_t*)calloc(element_length_in_bytes(tempG2)+8, sizeof(uint8_t));
    n = element_to_bytes(buff, tempG2);
    memcpy(buff+n, (uint8_t*)&i, sizeof(i));
    memcpy(buff+n+4, (uint8_t*)&j, sizeof(j));
    H_1(digest, buff, n+8);
    element_from_hash(tempG2, digest, 32);
    element_invert(tempZr, y_i);
    element_pow_zn(tempG22, g2, tempZr);
    element_mul(TK_i_j, tempG2, tempG22);
}

void formIndex(uint32_t id, char words[][30], int word_num)
{
    uint8_t buff[32];
    uint8_t *digest;
    int i =0;
    int j = 1;
    int n;
    Index_id[index_idx].id = id;
    Index_id[index_idx].wordnum = word_num;
    //构造TAG_id
    for (int idx = 0; idx < word_num; ++idx)
    {
        element_init_GT(Index_id[index_idx].TAG_id[idx].c1, pairing);
        element_init_GT(Index_id[index_idx].TAG_id[idx].c2, pairing);
//printf("%s, %d\n", words[i], sizeof((char*)words[i]));
        H(buff, (uint8_t*)(words[idx]), sizeof((char*)words[idx]));
        element_from_hash(tempG1, buff, 32);
        element_pairing(tempGT, tempG1, g2);
        element_pow_zn(Index_id[index_idx].TAG_id[idx].c1, tempGT, k1);
        element_pow_zn(Index_id[index_idx].TAG_id[idx].c2, tempGT, k2);
    }

    //构造delta_id,目前只涉及两个用户，j给i授权，即TK_i_j,包括自己的授权

    Index_id[index_idx].delta_id_num = 2;
    element_init_G2(Index_id[index_idx].delta_id[0], pairing);
    element_init_G2(Index_id[index_idx].delta_id[1], pairing);
    //恢复g2^(yi^-1)
    element_pow_zn(tempG2, MPK_i, x_j);//tempG2=g2^(xi*xj)=MPK_i^x_j
    digest = (uint8_t*)calloc(element_length_in_bytes(tempG2)+8, sizeof(uint8_t));
    n = element_to_bytes(digest, tempG2);
    memcpy(digest+n, (uint8_t*)&i, sizeof(i));
    memcpy(digest+n+4, (uint8_t*)&j, sizeof(j));
    H_1(buff, digest, n+8);
    element_from_hash(tempG2, buff, 32);

    element_div(tempG2, TK_i_j, tempG2);//g2^(yi^-1)

    element_pow_zn(Index_id[index_idx].delta_id[0], tempG2, k2);
    element_div(tempZr, k1, y_j);
    element_pow_zn(Index_id[index_idx].delta_id[1], g2, tempZr);

    ++index_idx;

}

int match(const char* word)
{
    uint8_t buff[32];
    int result_num = 0;


    for (int i=0; i<index_idx; ++i)
    {
    	element_div(tempZr, k2, y_i);
    	element_pow_zn(tempG2, g2, tempZr);

    	H(buff, (const uint8_t*)word, sizeof(word));
    	element_from_hash(tempG1, buff, 32);
    	element_pow_zn(tempG1, tempG1, y_i);

    	element_pairing(tempGT, tempG1, tempG2);
        int num = Index_id[i].wordnum;
        for (int j=0; j<num; ++j)
        {

            if (!element_cmp(Index_id[i].TAG_id[j].c2, tempGT))
            {
                printf("%d\n", Index_id[i].id);
                ++result_num;
                break;
            }
        }
    }
    printf("end\n");
    return result_num;
}

void clear()
{
    element_clear(g1);
    element_clear(g2);
    element_clear(p);

    element_clear(tempG1);
    element_clear(tempG2);
    element_clear(tempG22);
    element_clear(tempGT);
    element_clear(tempGT2);
    element_clear(p);
    element_clear(tempZr) ;
    element_clear(k1);
    element_clear(k2);
}

void read_index()
{
    FILE* fp;
    char* s;
    uint32_t doc_id;

    if ((fp=fopen("index_test", "r")) == NULL)
    {
        printf("no index file!\n");
        return ;
    }
    while (!feof(fp))
    {
        int i = 0;
        fgets(strLine, MAX_CHAR, fp);
        if( feof(fp) )
            break;
        strLine[strlen(strLine)-1] = '\0';
        s = strtok(strLine, " ");
        if (!s)
            return ;
        doc_id = atoi(s);

        while (true)
        {
            s = strtok(NULL, " ");
            if (!s)
                break;
            //printf("%s\n", s);
            strncpy(words_array[i++], s, sizeof(s));
        }
        formIndex(doc_id, words_array, i);
		printf("index:%d\n", doc_id);
    }
    fclose(fp);
}


void interact_search()
{
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
        n = match(input);
        gettimeofday(&end, NULL);
        time_use = (end.tv_sec-start.tv_sec)*1000000 + (end.tv_usec-start.tv_usec);//微秒
        printf("time_use:%f, result_doc:%d\n", time_use/1e6, n);
    }

}

int main(int argc, char **argv)
{
	int index_mem_use = 0;
	int user500_auth_mem_use = 0;

    keyGen();
    follow();

    gettimeofday(&start, NULL);
    read_index();
	gettimeofday(&end, NULL);

	time_use = (end.tv_sec-start.tv_sec)*1000000 + (end.tv_usec-start.tv_usec);//微秒
	printf("index construction: %f\n", time_use/1e6);
	printf("document:%d\n", index_idx);
    printf("index_num:%d\n", index_idx);
	for(int i=0; i< index_idx; ++i)
	{
		index_mem_use += sizeof(Index_id[i]) - sizeof(struct S_C )*(WORDNUM-Index_id[i].wordnum) ;
		index_mem_use += (element_length_in_bytes(Index_id[i].TAG_id[0].c1) + element_length_in_bytes(Index_id[i].TAG_id[0].c2))*Index_id[i].wordnum;
		index_mem_use += element_length_in_bytes(Index_id[i].delta_id[0]) + element_length_in_bytes(Index_id[i].delta_id[1]);
		  
	}
	printf("index memory used: %fM\n", ((double)index_mem_use)/1024/1024);
	
	user500_auth_mem_use += element_length_in_bytes(Index_id[0].delta_id[0])*500*5000;
	printf("500 user auth info memory used:%fM\n", ((double)user500_auth_mem_use)/1024/1024);

    printf("index construction complete...\n");

    interact_search();
    return 0;
}




