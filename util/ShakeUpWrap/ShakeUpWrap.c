#include "suw.h"
#include "config.h"
#include <stdio.h>
#include <string.h>

// make clean && make x86-64/ShakeUpWrap -j$(nproc)

int main(int argc, char* argv[]){
    bool enc = false;
    file_result_t result;
    char *filepath;
    for(int i = 1; i < argc; i++){
       if(strcmp("--encrypt", argv[i]) == 0 || strcmp("-e", argv[i]) == 0){
           enc = true;
       }else if (strcmp("--decrypt", argv[i]) == 0 || strcmp("-d", argv[i]) == 0) {
           enc = false;
       }else{
           filepath = argv[i];
       }
    }

    if(enc){
        result = encrypt(filepath);
        printf("%s\n", get_error_message(result));
    }else{
        result = decrypt(filepath);
        printf("%s\n", get_error_message(result));
    }
    return result;
}
