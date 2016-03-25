//
//  obfs_ws.c
//  ss-ws
//
//  Created by XuJing on 16/3/23.
//  Copyright © 2016年 XuJing. All rights reserved.
//

#include "obfs_ws.h"


typedef struct ws_simple_local_data {
    int has_sent_header;
    int has_recv_header;
    char *send_buffer;
    int send_buffer_size;
}ws_simple_local_data;

void ws_simple_local_data_init(ws_simple_local_data* local) {
    local->has_sent_header = 0;
    local->has_recv_header = 0;
    local->send_buffer = NULL;
    local->send_buffer_size = 0;
}

obfs * ws_simple_new_obfs() {
    obfs * self = new_obfs();
    self->l_data = malloc(sizeof(ws_simple_local_data));
    ws_simple_local_data_init((ws_simple_local_data*)self->l_data);
    return self;
}

void ws_simple_dispose(obfs *self) {
    ws_simple_local_data *local = (ws_simple_local_data*)self->l_data;
    if (local->send_buffer != NULL) {
        free(local->send_buffer);
        local->send_buffer = NULL;
    }
    free(local);
    dispose_obfs(self);
}

char ws_simple_hex(char c) {
    if (c < 10) return c + '0';
    return c - 10 + 'a';
}


int ws_simple_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity) {
    char *encryptdata = *pencryptdata;
    ws_simple_local_data *local = (ws_simple_local_data*)self->l_data;
    if (local->has_sent_header == 2) {
        return datalength;
    }
    
    local->send_buffer = (char*)realloc(local->send_buffer, local->send_buffer_size + datalength);
    memcpy(local->send_buffer + local->send_buffer_size, encryptdata, datalength);
    local->send_buffer_size += datalength;
    char * out_buffer = NULL;
    
    if (local->has_sent_header == 0) {
        char hostport[128];
        out_buffer = (char*)malloc(2048);
        
        memset(out_buffer, 0, 2048);

        if (self->server.param && strlen(self->server.param) == 0)
            self->server.param = NULL;
        if (self->server.port == 80)
            sprintf(hostport, "%s", (self->server.param ? self->server.param : self->server.host));
        else
            sprintf(hostport, "%s:%d", (self->server.param ? self->server.param : self->server.host), self->server.port);
        
        // LOGI("server.param : %s, server-host: %s", self->server.param, self->server.host);
        
        sprintf(out_buffer,
                "GET /%s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Accept-Language: en-US,en;q=0.8\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "DNT: 1\r\n"
                "Upgrade: websocket\r\n"
                "Connection: upgrade\r\n"
                "Sec-WebSocket-Protocol: chat, superchat\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n",
                "chat",
                hostport,
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36"
                );
        
        // LOGI("%s", out_buffer);
        
        datalength = strlen(out_buffer);
        
        local->has_sent_header = 1;
    } else if (datalength == 0) {
        // 直接发送数据
        
        // LOGI("has_sendt_header from 1 to 2");
        datalength = local->send_buffer_size;
        out_buffer = (char*)malloc(datalength);
        char *pdata = out_buffer;
        memcpy(pdata, local->send_buffer, local->send_buffer_size);
        free(local->send_buffer);
        local->send_buffer = NULL;
        local->has_sent_header = 2;
         
        
    } else {
        return 0;
    }
    
    
    if (*capacity < datalength) {
        *pencryptdata = (char*)realloc(*pencryptdata, *capacity = datalength * 2);
        encryptdata = *pencryptdata;
    }
    // LOGI("prepare to send %s", out_buffer);
    memmove(encryptdata, out_buffer, datalength);
    // LOGI("return datalenght  : %d", datalength);
    free(out_buffer);
    return datalength;
}

int ws_simple_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback) {
    
    ws_simple_local_data* local = (ws_simple_local_data*) self->l_data;

    *needsendback = 0;
    if (local->has_recv_header) {
        return datalength;
    }
    
    local->has_recv_header = 1;
    *needsendback = 1;
    return 0;
}
