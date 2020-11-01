#include "auth.h"



void loadIfNotExist(AuthHeader *auth_header, uint8_t method){
    
    for (size_t i = 0; i < auth_header->size; i++)
        if(auth_header->methods[i] == method)
            return;
    auth_header->methods[auth_header->size++] = method;
}

int chooseAuthMethod(HelloParser *p){

    //TODO por ahora pasamos el primero que encuentre, preguntarle a codagodne
    AuthHeader *aux = (AuthHeader *)p->data;
    if (aux->size == 0)
        return -1;
    
    return aux->methods[0];
}
