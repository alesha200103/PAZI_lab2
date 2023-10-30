 #include <stdio.h>
 #include <libakrypt.h>
 #include <stdbool.h>


ak_uint8* read_file(const char* filename, size_t* length){
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("No such file: %s\n", filename);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    rewind(file);
    ak_uint8* buffer = (ak_uint8*)malloc(*length);

    if (fread(buffer, 1, *length, file) < *length) {
        printf("Error while read file\n");
        free(buffer);
        fclose(file);
        exit(1);
    }
    fclose(file);
    return buffer;
}


void write_file(const char* filename, ak_uint8* buffer, size_t length) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Cannot open file %s\n", filename);
        exit(1);
    }
    if (fwrite(buffer, 1, length, file) < length) {
        printf("Error while write file\n");
        exit(1);
    }
    fclose(file);
}


void encrypt(const char* filename_plain, const char* filename_cipher, bool is_generate_key, const char* password){
    size_t length;
    ak_uint8* plain_data = read_file(filename_plain, &length);

    int error = ak_error_ok;
    int exitstatus = EXIT_FAILURE;
    struct bckey ctx;
    ak_uint8 key[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38  };
    ak_uint8 iv[8] = { 0x01, 0x02, 0x03, 0x04, 0x11, 0xaa, 0x4e, 0x12 };

    ak_bckey_create_magma( &ctx );

    if(is_generate_key){
        ak_bckey_set_key_from_password( &ctx, (ak_pointer)password, 8, (ak_pointer)"rand", 4 );
    }
    else{
        ak_bckey_set_key( &ctx, key, 32);
    }


    if(( error = ak_bckey_ofb( &ctx,
                                plain_data,
                                plain_data,
                                length,
                                iv,
                                8           
                            )) != ak_error_ok );

    write_file(filename_cipher, plain_data, length);
}


void decrypt(const char* filename_cipher, const char* filename_plain, bool is_generate_key, const char* password){
    encrypt(filename_cipher, filename_plain, is_generate_key, password);
}


int main(int argc, char **argv){

    const char *filename1, *filename2, *password=NULL;
    bool is_generate_key = false;


    for(int i = 1; i < argc; ++i){
        if(strcmp(argv[i], "--generatekey") == 0){
            if(i + 1 < argc){
                password = argv[i + 1];
            }
            else{
                printf("Not set password");
                exit(1);
            }
            is_generate_key = true;
		}
        if(strcmp(argv[i], "--encrypt") == 0){
            if(i + 1 < argc){
                filename1 = argv[i + 1];
            }
            if(i + 2 < argc){
                filename2 = argv[i + 2];
            }
            else{
                printf("Not set filename_plain or filename_cipher");
                exit(1);
            }
			encrypt(filename1, filename2, is_generate_key, password);
		}
        if(strcmp(argv[i], "--decrypt") == 0){
            if(i + 1 < argc){
                filename1 = argv[i + 1];
            }
            if(i + 2 < argc){
                filename2 = argv[i + 2];
            }
            else{
                printf("Not set filename_plain or filename_cipher");
                exit(1);
            }
			decrypt(filename1, filename2, is_generate_key, password);
		}
	}

    if( ak_libakrypt_create( NULL ) != ak_true ){
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    int error = ak_error_ok;
    int exitstatus = EXIT_FAILURE;
    if( error == ak_error_ok ) exitstatus = EXIT_SUCCESS;
    ak_libakrypt_destroy();
    return exitstatus;
    return 0;
}
