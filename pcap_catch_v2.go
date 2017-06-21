// Package pcap is a wrapper around the pcap library.
package main


/*
#cgo LDFLAGS: -L. -lcapturepcap -lpcap

#include <pcap.h>
#include "debug.h"
#include "cap_structs.h"
#include "counter.h"
#include "payload_cache.h"

payload_cache_t g_cache;

#define SNAP_LEN 1518

struct got_packet_args_t{
  void* callback;
  void* callback_args;
};
extern void gocallback_payload(void* func, void* args, char *tcp_payload, int length, void* extra);
static void call_gocallback(void* uargs, u_char *tcp_payload, int length, void* extra){
    struct got_packet_args_t* args = (struct got_packet_args_t*)uargs;
    gocallback_payload(args->callback, args->callback_args, tcp_payload, length, extra);
}

extern void gocallback_http_header(void*, void*, char*, char*);
static void go_print_http_header(void* go_func, const char *key, const char *val){
    gocallback_http_header(go_func, NULL, (char*)key, (char*)val);
}

// key is NULL at first line.
typedef void parse_line_cb(void* args, const char *key, const char *val);
int http_header_parse(parse_line_cb callback, void* go_func, char* payload, int payload_len);
static int http_header_parse_warp(void* go_func, char* payload, int payload_len){
    http_header_parse(go_print_http_header, go_func, payload, payload_len);
}


typedef void tcp_callback_t(void* args, u_char *tcp_payload, int length, void* extra);
void tcp_handler(struct cap_headers *headers, payload_cache_t *payload_cache, tcp_callback_t callback, void* args);

static void got_packet_cgo(u_char *uargs, const struct pcap_pkthdr *header, const u_char *packet){
    COUNTER_INC(package);
//    struct got_packet_args_t* args = (struct got_packet_args_t*)uargs;
    struct cap_headers cap_h;
    if(decode((u_char*)packet, header->caplen, &cap_h) == -1){
        return;
    }
    // print source and destination IP addresses
    IF_DEBUG(printf("       From: %s\n", inet_ntoa(*(struct in_addr*)&cap_h.ip.header.saddr)));
    IF_DEBUG(printf("         To: %s\n", inet_ntoa(*(struct in_addr*)&cap_h.ip.header.daddr)));
    if(cap_h.ip.header.protocol != IPPROTO_TCP){
      IF_DEBUG(printf("   Protocol: Not TCP.\n"));
      return;
    }
    IF_DEBUG(printf("   Src port: %d\n", cap_h.tcp.header.source));
    IF_DEBUG(printf("   Dst port: %d\n", cap_h.tcp.header.dest));

    if(cap_h.tcp.header.source==80 || cap_h.tcp.header.dest==80){
        COUNTER_INC(tcp_port_80_package);
    }

    // callback
    //printf("---payload[%d]---\n%s", cap_h.payload_len, cap_h.payload);
//     gocallback(args->callback, args->callback_args, cap_h.payload, cap_h.payload_len, NULL);
    tcp_handler(&cap_h, &g_cache, call_gocallback, uargs);
}

static void capture_n(int num_packets, const char *dev, const char *filter_exp,
               void* tcp_callback, void* cb_args){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    
    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
    }
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return;
    }

    if(filter_exp==NULL){
        filter_exp = "ip and tcp dst port 80 and (ip[2:2]>80)";
    }

    // get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
       fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if(handle==NULL){
       fprintf(stderr, "Couldn't open live for device %s: %s\n",
            dev, errbuf);
       return;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        return;
    }


    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        return;
    }

    struct got_packet_args_t got_packet_args = {
        .callback = tcp_callback,
        .callback_args = cb_args
    };
    printf("starting capture...\n");
    pcap_loop(handle, num_packets, got_packet_cgo, (u_char*)&got_packet_args);

    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    print_counter(&g_counter);
}




*/
import "C"

import (
    "unsafe"
    "fmt"
)



//export gocallback_payload
func gocallback_payload(f unsafe.Pointer, args unsafe.Pointer, tcp_payload *C.char, length C.int, extra unsafe.Pointer){
    (*(*func(unsafe.Pointer, *C.char, C.int, unsafe.Pointer))(unsafe.Pointer(&f)))(args, tcp_payload, length, extra)
}


//export gocallback_http_header
func gocallback_http_header(f unsafe.Pointer, args unsafe.Pointer, key *C.char, val *C.char){
    (*(*func(unsafe.Pointer, *C.char, *C.char))(unsafe.Pointer(&f)))(args, key, val)
}


func print_http_header(args unsafe.Pointer, key *C.char, val *C.char){
    if(key == nil){
       fmt.Println(C.GoString(val))
    }else{
       fmt.Println(C.GoString(key)+":"+C.GoString(val))
    }
}


var print_http_header_cb = print_http_header
func print_payload(args unsafe.Pointer, tcp_payload *C.char, length C.int, extra unsafe.Pointer){
    // fmt.Println(C.GoString(tcp_payload));
    fmt.Println("\n===got package===")
    cb := (*(*unsafe.Pointer)(unsafe.Pointer(&print_http_header_cb)))
    C.http_header_parse_warp(cb, tcp_payload, length)
}


var print_payload_cb = print_payload
func main() {
  cb := (*(*unsafe.Pointer)(unsafe.Pointer(&print_payload_cb)))
  C.capture_n(10, nil, C.CString("((ip[2:2]>80) and (tcp[13]&16!=0) and (tcp dst port 80))"), cb, nil)
}






