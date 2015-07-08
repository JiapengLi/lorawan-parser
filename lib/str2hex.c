#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

const char hex_tab[][16] = {
    "0123456789ABCDEF",
    "0123456789abcdef",
};

int char2hex(char c)
{
    int i;
    for(i = 0; i<16; i++){
        if( c == hex_tab[0][i] || c == hex_tab[1][i]){
            return i;
        }
    }
    return -1;
}

int word2hex(char *str, uint8_t *hex)
{
    int i, j, len;
    int h;
    len = strlen(str);
    j = 0;
    if(len%2){
        h = char2hex(str[0]);
        if(h<0){
            return -1;
        }
        hex[j] = h;
        j++;
        i=1;
    }else{
        i=0;
    }
    for(; i<len; i+=2){
        h = char2hex(str[i]);
        if(h<0){
            return -1;
        }
        hex[j] = h;
        hex[j] <<= 4;
        h = char2hex(str[i+1]);
        if(h<0){
            return -1;
        }
        hex[j] |= h;
        j++;
    }
    return j;
}

int str2hex(const char *str, uint8_t *hex, int max_len)
{
    int i, len, j, num;
    int start_index, para_len;
    char c;
    char *word;
    char *nstr;
    uint8_t *out;

    len = strlen(str);

    out = malloc(len);
    if(out == NULL){
        return -1;
    }

    nstr = malloc(len+1);
    if(nstr == NULL){
        return -2;
    }

    for(i=0, j=0; i<len; i++){
        c = str[i];
        if(c=='0'){
            if( ((len-1-i)>2) && (str[i+1]== 'x' || str[i+1] == 'X') ){
                nstr[j] = ' ';
                j++;
                i++;
            }else{
                nstr[j] = c;
                j++;
            }
        }else if(c==','){
            nstr[j] = ' ';
            j++;
        }else if( !( (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c == ' ') ){
            /** character invalid */
            return -1;
        }else{
            nstr[j] = c;
            j++;
        }
    }

    nstr[j] = '\0';
    len = strlen(nstr);

    j=0;
    for(i=0; i<len;){
        c = nstr[i];
        if(c != ' '){
            start_index = i;
            para_len = 0;
            while( (c != ' ') && (c != '\0') ){
                c = nstr[++i];
                para_len++;
            }
            if(para_len == 0){
                break;
            }
            word = malloc(para_len+1);
            memcpy(word, nstr+start_index, para_len);
            word[para_len] = '\0';
            num = word2hex(word, out+j);
            if(num < 0){
                return -2;
            }
            j+=num;
            free(word);
        }else{
            i++;
        }
    }

    memcpy(hex, out, (j>max_len?max_len:j));

    free(nstr);
    free(out);

    return j;
}
