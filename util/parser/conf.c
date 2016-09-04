#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "parson.h"
#include "conf.h"
#include "log.h"
#include "str2hex.h"
#include "lw.h"

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
        char len[10];
        sprintf(buf, " %d MESSAGE:\t", i);
        sprintf(len, "<%d>", head->len);
        log_puts(LOG_NORMAL, "%15s%6s %H", buf, len, head->buf, head->len);
        head = head->next;
        i++;
    }
}

void maccmd_print(message_t *head)
{
    int i = 0;

    while(head != NULL){
        char buf[100];
        char len[10];
        sprintf(buf, " %d MACCMD:\t", i);
        sprintf(len, "<%d>", head->len-1);
        log_puts(LOG_NORMAL, "%15s%6s [%02X] %H", buf, len, head->buf[0], head->buf+1, head->len-1);
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

const char *config_band_tab[]={
    "EU868",
    "EU434",
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
    char sbuf[100], slen[10];

    if(file == NULL){
        return -1;
    }

    /** Clear all flags */
    config_free(config);

    /* parsing json and validating output */
    jvroot = json_parse_file_with_comments(file);
    jtype = json_value_get_type(jvroot);
    if (jtype != JSONObject) {
        return -1;
    }
    joroot = json_value_get_object(jvroot);

    config->band = EU868;
    string = json_object_get_string(joroot, "band");
    if(string != NULL){
        for(i=0; i<sizeof(config_band_tab)/sizeof(char *); i++){
            if(0 == strcmp(string, config_band_tab[i])){
                config->band = (lw_band_t)i;
                break;
            }
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
                    log_puts(LOG_WARN, "Messages[%d] \"%s\" is not hex string\n", i, string);

                }
            }else{
                log_puts(LOG_WARN, "Messages item %d is not string\n", i);
            }
        }
    }else{
        log_puts(LOG_WARN, "Can't get \"messages\" payload array\n");
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
                    log_puts(LOG_WARN, "\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                    continue;
                }
            }else{
                string = json_object_get_string(jomaccmd, "direction");
                if(string != NULL){
                    int j;
                    len = strlen(string);
                    if(len>200){
                        log_puts(LOG_WARN, "\"maccommands\"[%d].direction \"%s\" too long\n", i, string);
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
                        log_puts(LOG_WARN, "\"maccommands\"[%d].MHDR \"%s\" must be 1 byte hex string\n", i, string);
                        continue;
                    }
                }else{
                    log_puts(LOG_WARN, "Can't recognize maccommand direction\n");
                    continue;
                }
            }
            string = json_object_get_string(jomaccmd, "command");
            if(string != NULL){
                len = str2hex(string, tmp, 255);
                if(len <= 0){
                    log_puts(LOG_WARN, "\"maccommands\"[%d].command \"%s\" is not hex string\n", i, string);
                    continue;
                }
            }else{
                log_puts(LOG_WARN, "c\"maccommands\"[%d].command is not string\n", i);
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
    log_puts(LOG_NORMAL, "%15s %s","BAND:\t", config_band_tab[EU868]);
    sprintf(sbuf, "NWKSKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->nwkskey, 16);
    sprintf(sbuf, "APPSKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->appskey, 16);
    sprintf(sbuf, "APPKEY:\t");
    sprintf(slen, "<%d>", 16);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->appkey, 16);
    sprintf(sbuf, "JOINR:\t");
    sprintf(slen, "<%d>", config->joinr_size);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->joinr, config->joinr_size);
    sprintf(sbuf, "JOINA:\t");
    sprintf(slen, "<%d>", config->joina_size);
    log_puts(LOG_NORMAL, "%15s%6s %H", sbuf, slen, config->joina, config->joina_size);
    pl_print(config->message);
    maccmd_print(config->maccmd);

    json_value_free(jvroot);
    return 0;
}
