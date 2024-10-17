//*************************************************************************//
// Titulo: Algoritmos de cifrado y descifrado PRESENT                      //
// Autores: Msc. Edwar Jacinto Gómez y Msc. Fernando Martínez Santa        //
// Versión: 1.1 (con librería PRESENT_32_bits.cpp)                         //
// Procesador: PC x86 int 32 bits                                          //
// Fecha: 12/08/2014                                                       //
// Comentarios: Archivo de cabecera con la funcion de cifrado PRESENT      //
//              con variable fijas de 32 bits, data[2] (64 bits) y key[3]  //
//              (96 bits, 80 utilizados)                                   //
//*************************************************************************//

#include "PRESENT_32_bits.h"

//---------------------------------------------------------------------------------
//Rutina principal de codificación del algoritmo PRESENT
void present(unsigned int *data_ext, unsigned int *key_ext) {
    
    //copia los datos de entrada
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data[i] = data_ext[i];  
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key[i] = key_ext[i];    
        
    //visualiza la clave original
    //printf("\nKey r0: 0x%X%X%X\t",key[2],key[1],key[0]);  
        
    //barrido de 31 rondas de codificación
    for(counter=1;counter<32;counter++){
        
        //primer paso
        data_xor_key(); //xor

        //segundo paso
        data_update();  //actualiza la información
        
        //tercer paso
        key_update();   //actualiza la clave
        
        //visualiza la clave
        //printf("key r%d: 0x%X%X%X\t",counter,key[2],key[1],key[0]);
        //if(counter%2==1) printf("\n");
    }
    
    //ultima ronda
    data_xor_key(); //printf("\n");//xor
    
    //copia los datos de salida
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data_ext[i] = data[i];  
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key_ext[i] = key[i];
}

//---------------------------------------------------------------------------------
//Rutina principal de decodificación del algoritmo PRESENT
void deco_present(unsigned int *data_ext, unsigned int *key_ext) {
    
    //copia los datos de entrada
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data[i] = data_ext[i];  
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key[i] = key_ext[i];
        
    //actualiza la clave hasta la ronda 31
    //printf("\nkey r0: 0x%X%X%X\t",key[2],key[1],key[0]);
    for(counter=1; counter<32; counter++ ) {
        key_update();   //actualiza la clave
        //printf("key r%d: 0x%X%X%X\t",counter,key[2],key[1],key[0]);
        //if(counter%2==1) printf("\n");
    }
        
    //visualiza la clave de arranque
    //printf("\nkey r31: 0x%X%X%X\t",key[2],key[1],key[0]); 
        
    //barrido de 31 rondas de decodificación
    for(counter=31;counter>0;counter--){
        
        //primer paso
        data_xor_key(); //xor

        //segundo paso
        data_update_i();    //actualiza la información
        
        //tercer paso
        key_update_i(); //actualiza la clave
        
        //visualiza la clave
        //printf("key r%d: 0x%X%X%X\t",counter-1,key[2],key[1],key[0]);
        //if(counter%2==1) printf("\n");
    }
    
    //ultima ronda
    data_xor_key(); //xor
    
    //copia los datos de salida
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data_ext[i] = data[i];  
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key_ext[i] = key[i];
}

//---------------------------------------------------------------------------------
bool read_bit_n_bits( unsigned int *datap, int index ){

    //calculo de la mascara y el indice
    i = (index/_NUM_BITS);      //index/32 deja solo numeros de 0 a 1
    mask = 0x00000001 << (index%_NUM_BITS); //index%32 deja solo numeros de 0 a 31
        
    //comprueba los indices
    if( index<=63 && index>=0 ){    //puede ser dato (63 a 0) o clave (79 a 0)
        
        if( (datap[i] & mask) != 0 )    //lee el bit
            return true;
        else
            return false;
    }
    else
        return false;
}

//---------------------------------------------------------------------------------
void write_bit_n_bits( unsigned int *datap, bool val, int index ){
    
    //calculo de la mascara y el indice
    i = (index/_NUM_BITS);      //index/32 deja solo numeros de 0 a 1
    mask = 0x00000001 << (index%_NUM_BITS); //index%32 deja solo numeros de 0 a 31  
    
    //comprueba los indices
    if( index<=((sizeof(datap)*8)-1) && index>=0 ){ //puede ser dato (63 a 0) o clave (79 a 0)
        
        if( val )
            datap[i] |= mask;   //escribe el 1 en el bit
        else
            datap[i] &= ~mask;  //escribe el 0 en el bit
    }
}

//---------------------------------------------------------------------------------
//p layer (reemplaza los valores del dato bit a bit)   
void p_layer( void ){
    
    value = read_bit_n_bits(data,0);        write_bit_n_bits(temp_data,value,0);
    value = read_bit_n_bits(data,1);        write_bit_n_bits(temp_data,value,16);
    value = read_bit_n_bits(data,2);        write_bit_n_bits(temp_data,value,32);
    value = read_bit_n_bits(data,3);        write_bit_n_bits(temp_data,value,48);
    value = read_bit_n_bits(data,4);        write_bit_n_bits(temp_data,value,1);
    value = read_bit_n_bits(data,5);        write_bit_n_bits(temp_data,value,17);
    value = read_bit_n_bits(data,6);        write_bit_n_bits(temp_data,value,33);
    value = read_bit_n_bits(data,7);        write_bit_n_bits(temp_data,value,49);
    value = read_bit_n_bits(data,8);        write_bit_n_bits(temp_data,value,2);
    value = read_bit_n_bits(data,9);        write_bit_n_bits(temp_data,value,18);
    value = read_bit_n_bits(data,10);       write_bit_n_bits(temp_data,value,34);
    value = read_bit_n_bits(data,11);       write_bit_n_bits(temp_data,value,50);
    value = read_bit_n_bits(data,12);       write_bit_n_bits(temp_data,value,3);
    value = read_bit_n_bits(data,13);       write_bit_n_bits(temp_data,value,19);
    value = read_bit_n_bits(data,14);       write_bit_n_bits(temp_data,value,35);
    value = read_bit_n_bits(data,15);       write_bit_n_bits(temp_data,value,51);
    value = read_bit_n_bits(data,16);       write_bit_n_bits(temp_data,value,4);
    value = read_bit_n_bits(data,17);       write_bit_n_bits(temp_data,value,20);
    value = read_bit_n_bits(data,18);       write_bit_n_bits(temp_data,value,36);
    value = read_bit_n_bits(data,19);       write_bit_n_bits(temp_data,value,52);
    value = read_bit_n_bits(data,20);       write_bit_n_bits(temp_data,value,5);
    value = read_bit_n_bits(data,21);       write_bit_n_bits(temp_data,value,21);
    value = read_bit_n_bits(data,22);       write_bit_n_bits(temp_data,value,37);
    value = read_bit_n_bits(data,23);       write_bit_n_bits(temp_data,value,53);
    value = read_bit_n_bits(data,24);       write_bit_n_bits(temp_data,value,6);
    value = read_bit_n_bits(data,25);       write_bit_n_bits(temp_data,value,22);
    value = read_bit_n_bits(data,26);       write_bit_n_bits(temp_data,value,38);
    value = read_bit_n_bits(data,27);       write_bit_n_bits(temp_data,value,54);
    value = read_bit_n_bits(data,28);       write_bit_n_bits(temp_data,value,7);
    value = read_bit_n_bits(data,29);       write_bit_n_bits(temp_data,value,23);
    value = read_bit_n_bits(data,30);       write_bit_n_bits(temp_data,value,39);
    value = read_bit_n_bits(data,31);       write_bit_n_bits(temp_data,value,55);
    value = read_bit_n_bits(data,32);       write_bit_n_bits(temp_data,value,8);
    value = read_bit_n_bits(data,33);       write_bit_n_bits(temp_data,value,24);
    value = read_bit_n_bits(data,34);       write_bit_n_bits(temp_data,value,40);
    value = read_bit_n_bits(data,35);       write_bit_n_bits(temp_data,value,56);
    value = read_bit_n_bits(data,36);       write_bit_n_bits(temp_data,value,9);
    value = read_bit_n_bits(data,37);       write_bit_n_bits(temp_data,value,25);
    value = read_bit_n_bits(data,38);       write_bit_n_bits(temp_data,value,41);
    value = read_bit_n_bits(data,39);       write_bit_n_bits(temp_data,value,57);
    value = read_bit_n_bits(data,40);       write_bit_n_bits(temp_data,value,10);
    value = read_bit_n_bits(data,41);       write_bit_n_bits(temp_data,value,26);
    value = read_bit_n_bits(data,42);       write_bit_n_bits(temp_data,value,42);
    value = read_bit_n_bits(data,43);       write_bit_n_bits(temp_data,value,58);
    value = read_bit_n_bits(data,44);       write_bit_n_bits(temp_data,value,11);                 
    value = read_bit_n_bits(data,45);       write_bit_n_bits(temp_data,value,27);
    value = read_bit_n_bits(data,46);       write_bit_n_bits(temp_data,value,43);
    value = read_bit_n_bits(data,47);       write_bit_n_bits(temp_data,value,59);
    value = read_bit_n_bits(data,48);       write_bit_n_bits(temp_data,value,12);
    value = read_bit_n_bits(data,49);       write_bit_n_bits(temp_data,value,28);
    value = read_bit_n_bits(data,50);       write_bit_n_bits(temp_data,value,44);
    value = read_bit_n_bits(data,51);       write_bit_n_bits(temp_data,value,60);
    value = read_bit_n_bits(data,52);       write_bit_n_bits(temp_data,value,13);
    value = read_bit_n_bits(data,53);       write_bit_n_bits(temp_data,value,29);
    value = read_bit_n_bits(data,54);       write_bit_n_bits(temp_data,value,45);
    value = read_bit_n_bits(data,55);       write_bit_n_bits(temp_data,value,61);
    value = read_bit_n_bits(data,56);       write_bit_n_bits(temp_data,value,14);
    value = read_bit_n_bits(data,57);       write_bit_n_bits(temp_data,value,30);
    value = read_bit_n_bits(data,58);       write_bit_n_bits(temp_data,value,46);
    value = read_bit_n_bits(data,59);       write_bit_n_bits(temp_data,value,62);
    value = read_bit_n_bits(data,60);       write_bit_n_bits(temp_data,value,15);
    value = read_bit_n_bits(data,61);       write_bit_n_bits(temp_data,value,31);
    value = read_bit_n_bits(data,62);       write_bit_n_bits(temp_data,value,47);
    value = read_bit_n_bits(data,63);       write_bit_n_bits(temp_data,value,63);
    
    //actualización
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data[i] = temp_data[i]; 
}

//---------------------------------------------------------------------------------
//p layer_i (reemplaza los valores del dato bit a bit) invertidamente       
void p_layer_i( void ){
    
    value = read_bit_n_bits(data,0);        write_bit_n_bits(temp_data,value,0);
    value = read_bit_n_bits(data,16);       write_bit_n_bits(temp_data,value,1);
    value = read_bit_n_bits(data,32);       write_bit_n_bits(temp_data,value,2);
    value = read_bit_n_bits(data,48);       write_bit_n_bits(temp_data,value,3);
    value = read_bit_n_bits(data,1);        write_bit_n_bits(temp_data,value,4);
    value = read_bit_n_bits(data,17);       write_bit_n_bits(temp_data,value,5);
    value = read_bit_n_bits(data,33);       write_bit_n_bits(temp_data,value,6);
    value = read_bit_n_bits(data,49);       write_bit_n_bits(temp_data,value,7);
    value = read_bit_n_bits(data,2);        write_bit_n_bits(temp_data,value,8);
    value = read_bit_n_bits(data,18);       write_bit_n_bits(temp_data,value,9);
    value = read_bit_n_bits(data,34);       write_bit_n_bits(temp_data,value,10);
    value = read_bit_n_bits(data,50);       write_bit_n_bits(temp_data,value,11);
    value = read_bit_n_bits(data,3);        write_bit_n_bits(temp_data,value,12);         
    value = read_bit_n_bits(data,19);       write_bit_n_bits(temp_data,value,13);
    value = read_bit_n_bits(data,35);       write_bit_n_bits(temp_data,value,14);
    value = read_bit_n_bits(data,51);       write_bit_n_bits(temp_data,value,15);
    value = read_bit_n_bits(data,4);        write_bit_n_bits(temp_data,value,16);
    value = read_bit_n_bits(data,20);       write_bit_n_bits(temp_data,value,17);
    value = read_bit_n_bits(data,36);       write_bit_n_bits(temp_data,value,18);
    value = read_bit_n_bits(data,52);       write_bit_n_bits(temp_data,value,19);
    value = read_bit_n_bits(data,5);        write_bit_n_bits(temp_data,value,20);                
    value = read_bit_n_bits(data,21);       write_bit_n_bits(temp_data,value,21);
    value = read_bit_n_bits(data,37);       write_bit_n_bits(temp_data,value,22);
    value = read_bit_n_bits(data,53);       write_bit_n_bits(temp_data,value,23);
    value = read_bit_n_bits(data,6);        write_bit_n_bits(temp_data,value,24);
    value = read_bit_n_bits(data,22);       write_bit_n_bits(temp_data,value,25);
    value = read_bit_n_bits(data,38);       write_bit_n_bits(temp_data,value,26);
    value = read_bit_n_bits(data,54);       write_bit_n_bits(temp_data,value,27);
    value = read_bit_n_bits(data,7);        write_bit_n_bits(temp_data,value,28);
    value = read_bit_n_bits(data,23);       write_bit_n_bits(temp_data,value,29);
    value = read_bit_n_bits(data,39);       write_bit_n_bits(temp_data,value,30);
    value = read_bit_n_bits(data,55);       write_bit_n_bits(temp_data,value,31);
    value = read_bit_n_bits(data,8);        write_bit_n_bits(temp_data,value,32);
    value = read_bit_n_bits(data,24);       write_bit_n_bits(temp_data,value,33);
    value = read_bit_n_bits(data,40);       write_bit_n_bits(temp_data,value,34);
    value = read_bit_n_bits(data,56);       write_bit_n_bits(temp_data,value,35);
    value = read_bit_n_bits(data,9);        write_bit_n_bits(temp_data,value,36);
    value = read_bit_n_bits(data,25);       write_bit_n_bits(temp_data,value,37);
    value = read_bit_n_bits(data,41);       write_bit_n_bits(temp_data,value,38);
    value = read_bit_n_bits(data,57);       write_bit_n_bits(temp_data,value,39);
    value = read_bit_n_bits(data,10);       write_bit_n_bits(temp_data,value,40);
    value = read_bit_n_bits(data,26);       write_bit_n_bits(temp_data,value,41);
    value = read_bit_n_bits(data,42);       write_bit_n_bits(temp_data,value,42);
    value = read_bit_n_bits(data,58);       write_bit_n_bits(temp_data,value,43);
    value = read_bit_n_bits(data,11);       write_bit_n_bits(temp_data,value,44);
    value = read_bit_n_bits(data,27);       write_bit_n_bits(temp_data,value,45);
    value = read_bit_n_bits(data,43);       write_bit_n_bits(temp_data,value,46);
    value = read_bit_n_bits(data,59);       write_bit_n_bits(temp_data,value,47);
    value = read_bit_n_bits(data,12);       write_bit_n_bits(temp_data,value,48);
    value = read_bit_n_bits(data,28);       write_bit_n_bits(temp_data,value,49);
    value = read_bit_n_bits(data,44);       write_bit_n_bits(temp_data,value,50);
    value = read_bit_n_bits(data,60);       write_bit_n_bits(temp_data,value,51);
    value = read_bit_n_bits(data,13);       write_bit_n_bits(temp_data,value,52);
    value = read_bit_n_bits(data,29);       write_bit_n_bits(temp_data,value,53);
    value = read_bit_n_bits(data,45);       write_bit_n_bits(temp_data,value,54);
    value = read_bit_n_bits(data,61);       write_bit_n_bits(temp_data,value,55);
    value = read_bit_n_bits(data,14);       write_bit_n_bits(temp_data,value,56);
    value = read_bit_n_bits(data,30);       write_bit_n_bits(temp_data,value,57);
    value = read_bit_n_bits(data,46);       write_bit_n_bits(temp_data,value,58);
    value = read_bit_n_bits(data,62);       write_bit_n_bits(temp_data,value,59);
    value = read_bit_n_bits(data,15);       write_bit_n_bits(temp_data,value,60);
    value = read_bit_n_bits(data,31);       write_bit_n_bits(temp_data,value,61);
    value = read_bit_n_bits(data,47);       write_bit_n_bits(temp_data,value,62);
    value = read_bit_n_bits(data,63);       write_bit_n_bits(temp_data,value,63);
    
    //actualización
    for(i=0; i<_NUM_VAR_DATA; i++ )
        data[i] = temp_data[i];
}

//---------------------------------------------------------------------------------
//s box layer (reemplaza los valores del dato en grupos de 4 bits)
void s_box_layer( void ){
                                
    //barrido por las 2 variables
    for(i=0; i<_NUM_VAR_DATA; i++){
        
        mask = 0x0000000F;  //mascara inicial
        
        //barrido por los 8nibles
        for(j=0; j<_NUM_NIBLE_DATA; j++){
            
            temp = data[i] & mask;  //extrae los bits del dato
            
            temp >>= (j*4);     //corre el numero de nibles a la derecha
            
            temp = s_box[temp]; //lee el contenido de la s box
            
            temp <<= (j*4);     //corre el numero de nibles a la derecha
            
            data[i] = data[i] & ~mask;  //borra los bits correspondientes
            
            data[i] = data[i] | temp;   //reemplaza por el contenido de la s box
            
            mask <<= 4;         //corre la mascara al siguiente nible
        }
    }
}

//---------------------------------------------------------------------------------
//s box layer_i (reemplaza los valores del dato en grupos de 4 bits) invertidamente
void s_box_layer_i( void ){
                                
    //barrido por las 2 variables
    for(i=0; i<_NUM_VAR_DATA; i++){
        
        mask = 0x0000000F;  //mascara inicial
        
        //barrido por los 8nibles
        for(j=0; j<_NUM_NIBLE_DATA; j++){
            
            temp = data[i] & mask;  //extrae los bits del dato
            
            temp >>= (j*4);     //corre el numero de nibles a la derecha
            
            temp = s_box_i[temp];   //lee el contenido de la s box
            
            temp <<= (j*4);     //corre el numero de nibles a la derecha
            
            data[i] = data[i] & ~mask;  //borra los bits correspondientes
            
            data[i] = data[i] | temp;   //reemplaza por el contenido de la s box
            
            mask <<= 4;         //corre la mascara al siguiente nible
        }
    }
}

//---------------------------------------------------------------------------------
//actualizacion de la información
void data_update( void ){
    
    //S box layer
    s_box_layer();
    
    //P box layer
    p_layer();  
}

//---------------------------------------------------------------------------------
//actualizacion de la información invertida
void data_update_i( void ){
    
    //P box layer invertida
    p_layer_i();    
    
    //S box layer invertida
    s_box_layer_i();    
}

//---------------------------------------------------------------------------------
//actualización de la clave
void key_update( void ){
    
    //corrimiento de 61 bits a la derecha
    temp = key[0] & 0x0007FFF8; //bit del 18 al 3 (16 bits)
    temp_key[2] = temp>>3;      //lo carga en la variable mas significativa corrido 3 veces d
    
    temp = key[0] & 0x00000007; //bit del 2 al 0 (3 bits)
    temp_key[1] = temp<<29;     //lo carga en la variable media corrido 29 veces i
    
    temp = key[2] & 0x0000FFFF; //bit del 79 al 64 (16 bits)
    temp_key[1] |= temp<<13;    //lo carga en la variable media con or corrido 13 veces i
    
    temp = key[1] & 0xFFF80000; //bit del 63 al 51 (13 bits)
    temp_key[1] |= temp>>19;    //lo carga en la variable media con or corrido 19 veces d
    
    temp = key[1] & 0x0007FFFF; //bit del 50 al 32 (19 bits)
    temp_key[0] = temp<<13; //lo carga en la variable menos significativa corrido 13 veces i
    
    temp = key[0] & 0xFFF80000; //bit del 31 al 19 (13 bits)
    temp_key[0] |= temp>>19;    //lo carga en la variable menos significativa corrido 19 veces d
    
    //paso por S box de los 4 MSB de la clave
    temp = temp_key[2] & 0x0000F000;    //enmascara bit 79 al 76
    
    temp >>= 12;                    //corre
    
    temp = s_box[temp];             //S box
    
    temp <<= 12;                    //corre de vuelta
    
    temp_key[2] &= ~0x0000F000;     //borra los bits correspondientes
            
    temp_key[2] |= temp;            //reemplaza por el contenido de la s box
    
    //xor con el contador
    temp = temp_key[0] & 0x000F8000;    //enmascara bit del 19 al 15
            
    temp >>= 15;                        //corre     
    
    temp ^= counter & 0x0000001F;
    
    temp <<= 15;                        //corre de vuelta
    
    temp_key[0] &= ~0x000F8000; //borra los bits correspondientes
            
    temp_key[0] |= temp;            //reemplaza por el contenido de la s box
    
    //actualización
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key[i] = temp_key[i];   
}

//---------------------------------------------------------------------------------
//actualización de la clave invertido
void key_update_i( void ){
    
    //corrimiento de 61 bits a la izquierda
    temp = key[1] & 0x1FFFE000; //bit del 60 al 45 (16 bits)
    temp_key[2] = temp>>13;     //lo carga en la variable mas significativa corrido 13 veces d
    
    temp = key[1] & 0x00001FFF; //bit del 44 al 32 (13 bits)
    temp_key[1] = temp<<19;     //lo carga en la variable media corrido 19 veces i
    
    temp = key[0] & 0xFFFFE000; //bit del 31 al 13 (19 bits)
    temp_key[1] |= temp>>13;    //lo carga en la variable media con or corrido 13 veces d
    
    temp = key[0] & 0x00001FFF; //bit del 12 al 0 (13 bits)
    temp_key[0] = temp<<19; //lo carga en la variable menos significativa corrido 19 veces i
    
    temp = key[2] & 0x0000FFFF; //bit del 79 al 64 (16 bits)
    temp_key[0] |= temp<<3; //lo carga en la variable menos significativa corrido 3 veces i
    
    temp = key[1] & 0xE0000000; //bit del 63 al 61 (3 bits)
    temp_key[0] |= temp>>29;    //lo carga en la variable menos significativa corrido 29 veces d
    
    //paso por S box de los 4 MSB de la clave
    temp = temp_key[0] & 0x00078000;    //enmascara bit 79 al 76 (18 al 15) corridos
    
    temp >>= 15;                    //corre
    
    temp = s_box_i[temp];           //S box invertido
    
    temp <<= 15;                    //corre de vuelta
    
    temp_key[0] &= ~0x00078000;     //borra los bits correspondientes
            
    temp_key[0] |= temp;            //reemplaza por el contenido de la s box
    
    //xor con el contador
    temp = temp_key[1] & 0x0000007C;    //enmascara bit del 19 al 15 (38 al 34 corridos)
            
    temp >>= 2;                     //corre     
    
    temp ^= counter & 0x0000001F;
    
    temp <<= 2;                     //corre de vuelta
    
    temp_key[1] &= ~0x0000007C; //borra los bits correspondientes
            
    temp_key[1] |= temp;            //reemplaza por el contenido de la s box
    
    //actualización
    for(i=0; i<_NUM_VAR_KEY; i++ )
        key[i] = temp_key[i];   
}

//---------------------------------------------------------------------------------
//operacion de xor entre la información y la clave (64 MSB)
//esta funcion es especifica para cada procesador dependiendo del número de bits
void data_xor_key( void ){
    
    //corre 16 bits la clave de 80 para tomar solo los 64 mas significativos
    for(i=0;i<_NUM_VAR_DATA;i++)
        temp_key[i] = ((key[i+1]<<16) & 0xFFFF0000) | ((key[i]>>16)& 0x0000FFFF);
    
    //xor entre la clave (64 MSB) y la información
    for(i=0;i<_NUM_VAR_DATA;i++)
        data[i] ^= temp_key[i];
}