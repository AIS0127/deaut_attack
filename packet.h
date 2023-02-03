#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>



typedef struct deauth_packet{
    u_int8_t version;
    u_int8_t pad;
    u_int16_t length;
    u_int32_t flag;
    u_int8_t pd[3];
    u_int16_t frame_control;
    u_int16_t duration;
    u_int8_t dest_addr[6];
    u_int8_t src_addr[6];
    u_int8_t bssid[6];
    u_int16_t sequence_number;
    u_int16_t fixed_parameter;
    
} __attribute__((__packed__)) deauth_packet;

typedef struct auth_packet{
    u_int8_t version;
    u_int8_t pad;
    u_int16_t length;
    u_int32_t flag;
    u_int8_t pd[3];
    u_int16_t frame_control;
    u_int16_t duration;
    u_int8_t dest_addr[6];
    u_int8_t src_addr[6];
    u_int8_t bssid[6];
    u_int16_t sequence_number;
    u_int16_t farg1;
    u_int16_t farg2;
    u_int16_t farg3;
    
} __attribute__((__packed__)) auth_packet;
