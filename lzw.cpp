#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "ap_int.h"
#include "murmur.h"
#include <time.h>
#include <stdio.h>
#include <bitset>

#define CODE_LENGTH 13

uint16_t to_cl_written; // = 0;
uint16_t to_cl_to_be_written; // = CODE_LENGTH;
uint16_t to_cl_capacity; // = 8;
uint16_t to_cl_idx;

void to_code_len(uint16_t num, unsigned char* op) {

    to_cl_to_be_written = CODE_LENGTH;
    unsigned char temp;

    while (to_cl_to_be_written != 0) {

        if (to_cl_to_be_written >= 8) {

            temp = num >> (to_cl_to_be_written - to_cl_capacity);
            op[to_cl_idx] |= temp;

            to_cl_written = to_cl_capacity;
            to_cl_to_be_written = to_cl_to_be_written - to_cl_written;
            to_cl_capacity = to_cl_capacity - to_cl_written;

            if (to_cl_capacity <= 0) { to_cl_idx++; to_cl_capacity = 8; }

        }

        if (to_cl_to_be_written < 8) {

            temp = num << (8 - to_cl_to_be_written);
            op[to_cl_idx] |= temp;

            to_cl_written = to_cl_to_be_written;
            to_cl_capacity = 8 - to_cl_written;
            to_cl_to_be_written = 0;

            if (to_cl_capacity <= 0) { to_cl_idx++; to_cl_capacity = 8; }

        }

    }

}

uint16_t in_the_table(ap_uint<96> *brute_lzw_table, int table_len, ap_uint<96> ip, uint8_t ip_len) {

    for (int j = 0; j < table_len; j++) {
        ap_uint<120> b_data = brute_lzw_table[j];
        if ((b_data >> 24) == ip) {
            //is in the table
            uint16_t b_code = b_data;
            return b_code;
        }
    }
    return 65535;
}


void encoding(unsigned char* ip, int len, unsigned char* op, int &how_much_written) {

    to_cl_written = 0;
    //to_cl_to_be_written = CODE_LENGTH;
    to_cl_capacity = 8;
    to_cl_idx = 0;

    //unsigned char hash_lzw_table[8192][18] = { 0 };
    ap_uint<96> brute_lzw_table[4096] = {0};

    //unsigned char brute_lzw_table[4096][18] = { 0 };
    ap_uint<96> hash_lzw_table[65536] = {0};

    /*
    ap_uint<8> my_array[32768];
    my_array[0] = ap_uint<8>(1);
    my_array[1] = ap_uint<8>(2);

    ap_uint<256> my_array[1024];
    my_array[0](7, 0) = ap_uint<8>(1);
    my_array[0](15, 8) = ap_uint<8>(2);
	*/

    uint16_t code = 256;
    int tar_pos;
    int tar_ind;
    int brute_table_written = 0;

    //int how_much_written = 0; //how much written in the op buffer

    //std::cout << "Encoding." << std::endl;

    ap_uint<96> p = 0;
    ap_uint<96> p_plus_c = 0;
    ap_uint<8> c = 0;

    uint32_t p_len = 0, p_plus_c_len = 0; // the largest p or p_plus_c can grow is 15


    p = ip[0];
    //std::cout << "p = " << char(p) << std::endl;
    p_len++;
    //std::cout << "p_len = " << p_len << std::endl;

    int i = 0;

    //std::cout << "\n\n\nEntering the while loop\n\n" << std::endl;

    int c_counter = 0;

    while(i < len) {



        p_plus_c = p; // writing p to p+c
        p_plus_c_len = p_len;


       //std::cout << "p = " << char(p) << std::endl;
       //std::cout << "p_len = " << p_len << std::endl;

        //adding c to p
        if ( (i != len - 1) && (p_plus_c_len < 12) ) {
            c = ip[i + 1];
            //std::cout << "c = " << char(c) << std::endl;
            p_plus_c = p_plus_c << 8; //* p_len; //making space to add c

            p_plus_c |= c; //adding c to p+c;
            p_plus_c_len++;

            //std::bitset<120> bs_pc(p_plus_c);
            //std::cout << "Appending c to p..." << std::endl;
            //std::cout << "p_plus_c bits = " << bs_pc << std::endl;
           // std::cout << "p_plus_c_len = " << p_plus_c_len << std::endl;
        }

        unsigned char p_plus_c_string[12] = { 0 };
        for (int idxxx = 0; idxxx < p_plus_c_len; idxxx++) {
            p_plus_c_string[idxxx] = (p_plus_c >> idxxx*8);
        }

        //std::cout << "p_plus_c_string = ";
        for(int abc = p_plus_c_len-1; abc>=0; abc--){
        	//std::cout << p_plus_c_string[abc] << " ";
        }

        //std::cout << std::endl;

        void *ptr_to_pc = &p_plus_c;
        uint32_t hash = MurmurHash2(ptr_to_pc, p_plus_c_len, 1);
        uint32_t str_hash = MurmurHash2(p_plus_c_string, p_plus_c_len, 1);
        //std::cout << "Hash of the string from the 144 bit p_plus_c is: " << hash << std::endl;
        //std::cout << "Hash of the string from the p_plus_c_string is: " << str_hash << std::endl;

        ap_uint<13> hash_b13 = hash;

        ap_uint<16> hash_b16 = hash;
        ap_uint<14> hash_b14 = hash;
        ap_uint<15> hash_b15 = hash;


        //std::cout << "Bottom 13 bits of the hash are: " << hash_b13 << std::endl;
        //std::cout << "Bottom 14 bits of the hash are: " << hash_b14 << std::endl;
        //std::cout << "Bottom 15 bits of the hash are: " << hash_b15 << std::endl;
        //std::cout << "Bottom 16 bits of the hash are: " << hash_b16 << std::endl;



        ap_uint<96> t_data = hash_lzw_table[hash_b16];


        if(p_plus_c_len > 1){

			if (t_data != 0) {

				ap_uint<96> t_data_string = t_data >> 24;

				//std::cout << "\nSomething is written at the hash location.\n" << std::endl;

				if (t_data_string != p_plus_c) { //\

					//std::cout << "\n\n\n COLLISION \n\n\nLooking up in the brute force table now." << std::endl;
					c_counter++;

					uint16_t result = in_the_table(brute_lzw_table, brute_table_written, p_plus_c, p_plus_c_len);

					if(result != 65535){


						//std::cout << "\nThe string is present in the brute force table. So looking for a longer match.\n" << std::endl;

						p = 0; p = p_plus_c;
						p_len = p_plus_c_len;

					}
					else {

						if (p_len == 1) {
							to_code_len(uint16_t(p), op);
							how_much_written++;
							//std::cout << "Writing " << uint16_t(p) << " to the op buffer" << std::endl;
						}
						else {
							uint16_t data_code = 0;
							data_code = t_data;
							to_code_len(data_code, op);
							how_much_written++;
							//std::cout << "Writing " << data_code << " to the op buffer." << std::endl;
						}
						//std::cout << "The string is not present in the brute force table, but in the hash table it was, and a collision occurred.";
						//std::cout << "\nWriting to the brute force hash table." << std::endl;
						ap_uint<96> data_to_add = (p_plus_c << 24) | (p_plus_c_len << 16) | (code);
						brute_lzw_table[brute_table_written] = data_to_add;
						//std::cout << "Writing the string and corresponding code of " << code << " to the brute table" << std::endl;
						brute_table_written++;
						code++;


						p = 0; p = c;
						p_len = 1;
					}

				}
				else {
					p = 0; p = p_plus_c;
					p_len = p_plus_c_len;
				}


			}
			else {


				if (p_len == 1) {
					to_code_len(uint16_t(p), op);
					how_much_written++;
					//std::cout << "Writing " << uint16_t(p) << " to the op buffer" << std::endl;
				}
				else {
					uint16_t data_code = 0;
					void *ptr_to_p = &p;
					uint32_t hash = MurmurHash2(ptr_to_p, p_len, 1);
					uint16_t hash_o16 = hash;

					ap_uint<96> h_data = hash_lzw_table[hash_o16];
					data_code = h_data;
					to_code_len(data_code,op);
					//std::cout << "Writing " << data_code << " to the op buffer." << std::endl;
					how_much_written++;
				}

				ap_uint<96> data_to_add = (p_plus_c << 24) | (p_plus_c_len << 16) | (code);

				hash_lzw_table[hash_b16] = data_to_add;
				//std::cout << "Writing the string and corresponding code of " << code << " to the hash table" << std::endl;
				code++;

				p = 0; p = c;
				p_len = 1;
			}
    	}
        else{
        	to_code_len(uint16_t(p), op);
        	how_much_written++;
        	//std::cout << "Writing " << uint16_t(p) << " to the op buffer" << std::endl;
        }
        c = 0;
        i++;

    }

    std::cout << "Collision counter: " << c_counter << std::endl;
    std::cout << "Brute table written = " << brute_table_written << std::endl;
}






