#include "suw.h"
#include "config.h"
#include <stdio.h>

int main(int argc, char* argv[]){
    bool enc = false;
    file_buffer_t buffer;
    file_read_result_t result;
    char *filepath;
    for(int i = 1; i < argc; i++){
       if(strcmp("--encrypt", argv[i]) == 0){
           enc = true;
       }else if (strcmp("--decrypt", argv[i]) == 0) {
           enc = false;
       }else{
           filepath = argv[i];
       }
    }

    result = read_large_file(filepath, &buffer);
    printf("%s\n", get_error_message(result));
    if(enc){
        result = encrypt(&buffer);
        printf("%s\n", get_error_message(result));
    }else{
        result = decrypt(&buffer);
        printf("%s\n", get_error_message(result));
    }
    return result;
}
