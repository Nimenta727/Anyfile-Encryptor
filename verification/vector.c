/* Test-only deterministic wire-format generator. Never use for real encryption. */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int argon2id_hash_raw(uint32_t,uint32_t,uint32_t,const void*,size_t,const void*,size_t,void*,size_t);
static void die(void){fputs("vector generation failed\n",stderr);exit(1);}
static void put(unsigned char *p,uint64_t n,int len){while(len){p[--len]=(unsigned char)n;n>>=8;}}
static void hm(const unsigned char *k,size_t kl,const unsigned char *m,size_t ml,unsigned char *o){unsigned int n;if(!HMAC(EVP_sha256(),k,(int)kl,m,ml,o,&n)||n!=32)die();}
static void field(unsigned char **p,const void *s,size_t n){put(*p,n,4);*p+=4;memcpy(*p,s,n);*p+=n;}
static void expand(const unsigned char *k,const char *label,const unsigned char *id,unsigned suite,const unsigned char *extra,size_t ne,unsigned char *o){unsigned char b[128],*p=b,s[2];put(s,suite,2);field(&p,"MOSAIC-HDT/v2",13);field(&p,label,strlen(label));field(&p,id,16);field(&p,s,2);if(ne)field(&p,extra,ne);*p++=1;hm(k,32,b,p-b,o);}
static void enc(const unsigned char *k,const unsigned char *aad,int al,const unsigned char *p,int pl,unsigned char *o){unsigned char iv[12]={0};int n=0,z=0;EVP_CIPHER *c=EVP_CIPHER_fetch(NULL,"AES-256-GCM-SIV",NULL);EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();if(!c||!ctx||!EVP_EncryptInit_ex2(ctx,c,k,iv,NULL)||!EVP_EncryptUpdate(ctx,NULL,&n,aad,al)||!EVP_EncryptUpdate(ctx,o,&n,p,pl)||n!=pl||!EVP_EncryptFinal_ex(ctx,o+n,&z)||z||!EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,o+pl))die();EVP_CIPHER_CTX_free(ctx);EVP_CIPHER_free(c);}
int main(int argc,char **argv){unsigned suite=argc>1?(unsigned)atoi(argv[1]):1;unsigned mem[]={0,65536,262144,524288,1048576};if(suite<1||suite>4)die();unsigned char mat[65536],h[204]={0},id[16],sp[32],st[32],root[32],kt[32],kp[32],prk[32],kw[32],kc[32],kh[32],kd[32],kf[32],ki[32],d[32],b[256],*p=b,rec[13]={1},aad[45],out[48],counts[16]={0};
 for(size_t i=0;i<sizeof mat;i++)mat[i]=(unsigned char)(i%251);for(int i=0;i<32;i++){sp[i]=i;st[i]=32+i;root[i]=64+i;if(i<16)id[i]=96+i;}
 memcpy(h,"MOSHDT02",8);put(h+8,2,2);put(h+10,suite,2);memcpy(h+12,id,16);memcpy(h+28,sp,32);memcpy(h+60,st,32);
 field(&p,"test-alpha-001",14);field(&p,"test-beta-002",13);field(&p,"test-gamma-003",14);if(argon2id_hash_raw(3,mem[suite],4,b,p-b,sp,32,kp,32))die();hm(st,32,mat,sizeof mat,kt);hm(kt,32,kp,32,prk);expand(prk,"wrap",id,suite,NULL,0,kw);expand(prk,"commit",id,suite,NULL,0,kc);hm(kc,32,h,92,h+92);enc(kw,h,124,root,32,h+124);expand(root,"header",id,suite,NULL,0,kh);expand(root,"data",id,suite,NULL,0,kd);expand(root,"final",id,suite,NULL,0,kf);hm(kh,32,h,172,h+172);SHA256(h,204,d);
 put(rec+9,3,4);memcpy(aad,d,32);memcpy(aad+32,rec,13);expand(kd,"chunk",id,suite,rec+1,8,ki);enc(ki,aad,45,(const unsigned char*)"abc",3,out);if(fwrite(h,1,204,stdout)!=204||fwrite(rec,1,13,stdout)!=13||fwrite(out,1,19,stdout)!=19)die();put(counts,1,8);put(counts+8,3,8);aad[32]=2;enc(kf,aad,33,counts,16,out);if(fputc(2,stdout)==EOF||fwrite(out,1,32,stdout)!=32)die();return 0;}
