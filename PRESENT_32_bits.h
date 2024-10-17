//*************************************************************************//
// Titulo: Algoritmos de cifrado y descifrado PRESENT                      //
// Autores: Msc. Edwar Jacinto Gómez y Msc. Fernando Martínez Santa        //
// Versión: 1.1 (con librería PRESENT_32_bits.h)                           //
// Procesador: PC x86 int 32 bits                                          //
// Fecha: 12/08/2014                                                       //
// Comentarios: Archivo de cabecera con la funcion de cifrado PRESENT      //
//              con variable fijas de 32 bits, data[2] (64 bits) y key[3]  //
//              (96 bits, 80 utilizados)                                   //
//*************************************************************************//

#ifndef PRESENT_32_BITS_H
#define PRESENT_32_BITS_H

//definición de restricciones del procesador
#define _NUM_BITS       32
#define _NUM_VAR_KEY    3
#define _NUM_VAR_DATA   2
#define _NUM_NIBLE_DATA 8


//declara las variables de 32 bits
unsigned int key[3];
unsigned int data[2];
unsigned int temp_key[3];
unsigned int temp_data[2];

unsigned int counter;   //contador de ciclos (vueltas)
unsigned int mask;      //mascara de lectura
unsigned int i,j;       //indices generales
bool value;             //valor de un bit
unsigned int temp;      //variable temporal

//definición del s box
const unsigned int s_box[16] = {    0xC,
                                    0x5,
                                    0x6,
                                    0xB,
                                    0x9,
                                    0x0,
                                    0xA,
                                    0xD,
                                    0x3,
                                    0xE,
                                    0xF,
                                    0x8,
                                    0x4,
                                    0x7,
                                    0x1,
                                    0x2 };
//definición del s box invertido  
const unsigned int s_box_i[16] = {  0x5,
                                    0xE,
                                    0xF,
                                    0x8,
                                    0xC,
                                    0x1,
                                    0x2,
                                    0xD,
                                    0xB,
                                    0x4,
                                    0x6,
                                    0x3,
                                    0x0,
                                    0x7,
                                    0x9,
                                    0xA }; 

//prototipos de las funciones
bool read_bit_n_bits( unsigned int *datap, int index );
void write_bit_n_bits( unsigned int *datap, bool val, int index );
void p_layer( void );
void s_box_layer( void );
void data_update( void );
void key_update( void );
void data_xor_key( void );

//funciones invertidas
void p_layer_i( void );
void s_box_layer_i( void );
void data_update_i( void );
void key_update_i( void );

//funciones principales
void present(unsigned int *data_ext, unsigned int *key_ext);
void deco_present(unsigned int *data_ext, unsigned int *key_ext);

#endif