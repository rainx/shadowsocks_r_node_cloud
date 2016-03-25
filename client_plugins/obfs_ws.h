//
//  obfs_ws.h
//  ss-ws
//
//  Created by XuJing on 16/3/23.
//  Copyright © 2016年 XuJing. All rights reserved.
//

#ifndef obfs_ws_h
#define obfs_ws_h

#include <stdio.h>

obfs * ws_simple_new_obfs();
void ws_simple_dispose(obfs *self);

int ws_simple_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity);
int ws_simple_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback);

#endif /* obfs_ws_h */
