#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "parson.h"
#include "conf.h"
#include "log.h"
#include "str2hex.h"
#include "lorawan.h"

void pl_insert(message_t **head, message_t *new_node)
{
    message_t *tmp;

    if(*head == NULL){
        *head = new_node;
    }else{
        tmp = *head;
        while(tmp->next != NULL){
            tmp = tmp->next;
        }
        tmp->next = new_node;
    }
}

void pl_free(message_t **head)
{
    message_t *curr;

    while ((curr = *head) != NULL) { // set curr to head, stop if list empty.
        *head = (*head)->next;          // advance head to next element.
        if(curr->buf != NULL){
            free(curr->buf);
        }
        free(curr);                // delete saved pointer.
    }
    *head = NULL;
}

void pl_print(message_t *head)
{
    int i = 0;

    while(head != NULL){
        char buf[100];
        sprintf(buf, " %d MESSAGE:\t", i);
        printf("%15s",buf);
        putlen(head->len);
        puthbuf(head->buf, head->len);
        printf("\n");
        head = head->next;
        i++;
    }
}

void maccmd_print(message_t *head)
{
    int i = 0;

    while(head != NULL){
        char buf[100];
        sprintf(buf, " %d MACCMD:\t", i);
        printf("%15s",buf);
        putlen(head->len-1);
        printf("[%02X] ", head->buf[0]);
        puthbuf(head->buf+1, head->len-1);
        printf("\n");
        head = head->next;
        i++;
    }
}

void config_free(config_t *config)
{
    config->flag = 0;
    if(config->joina != NULL){
        free(config->joina);
    }
    if(config->joinr != NULL){
        free(config->joinr);
    }
    pl_free(&config->message);
    pl_free(&config->maccmd);
}

const char *config_band_tab[LW_BAND_MAX_NUM]={
    "EU868",
    "US915",
    "CN780",
    "EU433",
    "CUSTOM",
};

int config_parse(const char *file, config_t *config)
{
    JSON_Value *jvroot;
    JSON_Object *joroot;
    JSON_Object *jomaccmd;
    JSON_Array *jarray;
    JSON_Value_Type jtype;
    const char *string;
    int ret;
    int i;

    if(file == NULL){
        return -1;
    }

    /** Clear all flags */
    config_free(config);

    printf("Start parsing configuration file....\n\n");

    /* parsing json and validating output */
    jvroot = json_parse_file_with_comments(file);
    jtype = json_value_get_type(jvroot);
    if (jtype != JSONObject) {
        return -1;
    }
    joroot = json_value_get_object(jvroot);

    string = json_object_get_string(joroot, "band");
    if(string == NULL){
        config->band = LW_BAND_EU868;
    }else{
        for(i=0; i<LW_BAND_MAX_NUM; i++){
            if(0 == strcmp(string, config_band_tab[i])){
                config->band = (lw_band_t)i;
                break;
            }
        }
        if(i==LW_BAND_MAX_NUM){
            config->band = LW_BAND_EU868;
        }
    }

    string = json_object_dotget_string(joroot, "key.nwkskey");
    if(string != NULL){
        if(str2hex(string, config->nwkskey, 16) == 16){
            config->flag |= CFLAG_NWKSKEY;
        }
    }

    string = json_object_dotget_string(joroot, "key.appskey");
    if(string != NULL){
        if(str2hex(string, config->appskey, 16) == 16){
            config->flag |= CFLAG_APPSKEY;
        }
    }

    string = json_object_dotget_string(joroot, "key.appkey");
    if(string != NULL){
        if(str2hex(string, config->appkey, 16) == 16){
            config->flag |= CFLAG_APPKEY;
        }
    }

    ret = json_object_dotget_boolean(joroot, "join.key");
    if(ret==0){
        //printf("Join key false\n");
        config->joinkey = false;
    }else if(ret==1){
        //printf("Join key true\n");
        config->joinkey = true;
    }else{
        //printf("Unknown join key value\n");
        config->joinkey = false;
    }

    string = json_object_dotget_string(joroot, "join.request");
    if(string != NULL){
        uint8_t tmp[255];
        int len;
        len = str2hex(string, tmp, 255);
        if(len>0){
            config->flag |= CFLAG_JOINR;
            config->joinr = malloc(len);
            if(config->joinr == NULL){
                return -2;
            }
            config->joinr_size = len;
            memcpy(config->joinr, tmp, config->joinr_size);
        }
    }

    string = json_object_dotget_string(joroot, "join.accept");
    if(string != NULL){
        uint8_t tmp[255];
        int len;
        len = str2hex(string, tmp, 255);
        if(len>0){
            config->flag |= CFLAG_JOINA;
            config->joina = malloc(len);
            if(config->joina == NULL){
                return -3;
            }
            config->joina_size = len;
            memcpy(config->joina, tmp, config->joina_size);
        }
    }

    jarray = json_object_get_array(joroot, "messages");
    if(jarray != NULL){
        uint8_t tmp[255];
        for (i = 0; i < json_array_get_count(jarray); i++) {
            string = json_array_get_string(jarray, i);
            if(string!=NULL){
                int len = str2hex(string, tmp, 255);
                if(len>0){
                    message_t *pl = malloc(sizeof(message_t));
                    memset(pl, 0, sizeof(message_t));
                    if(pl == NULL){
                        return -3;
                    }
                    pl->buf = malloc(len);
                    if(pl->buf == NULL){
                        return -3;
                    }
                    pl->len = len;
                    memcpy(pl->buf, tmp, pl->len);
                    pl_insert(&config->message, pl);
                }else{
                    printf("Messages[%d] \"%s\" is not hex string\n", i, string);

                }
            }else{
                printf("Messages item %d is not string\n", i);
            }
        }
    }else{
        printf("Can't get payload array\n");
    }

    jarray = json_object_get_array(joroot, "maccommands");
    if(jarray != NULL){
        uint8_t mhdr;
        int len;
        uint8_t tmp[255];
        for (i = 0; i < json_array_get_count(jarray); i++) {
            jomaccmd = json_array_get_object(jarray, i);
            string = json_object_get_string(jomaccmd, "MHDR");
            if(string != NULL){
                len = str2hex(string, &mhdr, 1);
                if(len != 1){
                    printf("\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                    continue;
                }
            }else{
                string = json_object_get_string(jomaccmd, "direction");
                if(string != NULL){
                    int j;
                    len = strlen(string);
                    if(len>200){
                        printf("\"maccommands\"[%d].direction \"%s\" too long\n", i, string);
                        continue;
                    }
                    for(j=0; j<len; j++){
                        tmp[j] = tolower(string[j]);
                    }
                    tmp[j] = '\0';
                    if(0==strcmp((char *)tmp, "up")){
                        mhdr = 0x80;
                    }else if(0==strcmp((char *)tmp, "down")){
                        mhdr = 0xA0;
                    }else{
                        printf("\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                        continue;
                    }
                }else{
                    printf("Can't recognize maccommand direction\n");
                    continue;
                }
            }
            string = json_object_get_string(jomaccmd, "command");
            if(string != NULL){
                len = str2hex(string, tmp, 255);
                if(len <= 0){
                    printf("\"maccommands\"[%d].command \"%s\" is not hex string\n", i, string);
                    continue;
                }
            }else{
                printf("c\"maccommands\"[%d].command is not string\n", i);
                continue;
            }
            message_t *pl = malloc(sizeof(message_t));
            memset(pl, 0, sizeof(message_t));
            if(pl == NULL){
                return -3;
            }
            pl->buf = malloc(len+1);
            if(pl->buf == NULL){
                return -3;
            }
            pl->len = len+1;
            pl->buf[0] = mhdr;
            pl->next = 0;
            memcpy(pl->buf+1, tmp, pl->len-1);
            pl_insert(&config->maccmd, pl);
        }
    }

    log_line();
    printf("%15s %s\n","BAND:\t", config_band_tab[LW_BAND_EU868]);
    printf("%15s","NWKSKEY:\t");
    putlen(16);
    puthbuf(config->nwkskey, 16);
    printf("\n");
    printf("%15s","APPSKEY:\t");
    putlen(16);
    puthbuf(config->appskey, 16);
    printf("\n");
    printf("%15s","APPKEY:\t");
    putlen(16);
    puthbuf(config->appkey, 16);
    printf("\n");
    printf("%15s","JOINR:\t");
    putlen(config->joinr_size);
    puthbuf(config->joinr, config->joinr_size );
    printf("\n");
    printf("%15s","JOINA:\t");
    putlen(config->joina_size);
    puthbuf(config->joina, config->joina_size );
    printf("\n");
    pl_print(config->message);
    maccmd_print(config->maccmd);

    json_value_free(jvroot);
    return 0;
}
