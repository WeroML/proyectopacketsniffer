/*
 * packetsniffer.c
 * 
 * ESTRUCTURA DE UN PAQUETE
 * [HEADER]-[IP]-[TRANSPORT LAYER]
 * 
 * HEADER = 0
 * IP = link_hdr_length
 * TRANSPORT LAYER = 4 * link_hdr_length
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <pthread.h>

//Constantes para la interfaz gráfica
#define WINDOW_HEIGHT 20
#define WINDOW_WIDTH 80
#define START_Y 2
#define START_X 2
#define FILTER_BUFFER_SIZE 512  // Aumentamos el tamaño del buffer

WINDOW *main_window;
WINDOW *packet_window;
WINDOW *filter_window;        // Ventana para la configuración de filtros
int current_line = 1;
int scanning = 0;
int link_hdr_length = 0;
pcap_t *capdev = NULL;
pthread_t capture_thread;
int nFiltroActivo=0; //Variable para saber que filtro está activo, 1=SRC IP, 2=DST IP, 3=Protocolo, 4=Source Port
char filters[FILTER_BUFFER_SIZE] = ""; //Para almacenar que filtro se va a ocupar
char filter_value[FILTER_BUFFER_SIZE] = ""; //Para almacenar el valor del filtro que se va a ocupar


// Función para limpiar y cerrar ncurses apropiadamente
void cleanup() {
    if (main_window) delwin(main_window);
    if (packet_window) delwin(packet_window);
    endwin();
}

// Función para configurar los filtros
void showFilterConfig(){
    // Crear ventana de filtros
    filter_window = newwin(10, 60, (LINES - 10) / 2, (COLS - 60) / 2);
    box(filter_window, 0, 0);
    
    // Habilitar entrada de teclado para la ventana
    keypad(filter_window, TRUE);
    
    // Mostrar opciones de filtro
    mvwprintw(filter_window, 1, 2, "Configuración de Filtros");
    mvwprintw(filter_window, 3, 2, "1. Filtrar por IP origen");
    mvwprintw(filter_window, 4, 2, "2. Filtrar por IP destino");
    mvwprintw(filter_window, 5, 2, "3. Filtrar por protocolo (tcp/udp/icmp)");
    mvwprintw(filter_window, 6, 2, "4. Filtrar por puerto origen");
    mvwprintw(filter_window, 8, 2, "Presione ESC para cancelar");
    
    wrefresh(filter_window);
    
    // Manejar entrada del usuario
    int choice;
    while ((choice = wgetch(filter_window)) != 27) { // 27 es ESC
        if (choice >= '1' && choice <= '4') {

            // Limpiar línea de entrada
            wmove(filter_window, 7, 2);
            wclrtoeol(filter_window);
            box(filter_window, 0, 0);
            
            // Solicitar valor del filtro
            echo();
            curs_set(1);
            wmove(filter_window, 7, 2);
            wprintw(filter_window, "Ingrese valor: ");
            wrefresh(filter_window);
            
            // Leer valor del filtro
            wgetnstr(filter_window, filter_value, 255);
            
            // Construir string de filtro para pcap
    switch(choice) {
        case '1':
            if (snprintf(filters, FILTER_BUFFER_SIZE, "src host %s", filter_value) >= FILTER_BUFFER_SIZE) {
                // Manejar error de buffer insuficiente
                mvwprintw(filter_window, 7, 2, "Error: Valor del filtro demasiado largo");
                wrefresh(filter_window);
                sleep(2);
                filters[0] = '\0';  // Limpiar el buffer
                nFiltroActivo = 0;
                break;
            }
            nFiltroActivo = 1;
            break;
        case '2':
            if (snprintf(filters, FILTER_BUFFER_SIZE, "dst host %s", filter_value) >= FILTER_BUFFER_SIZE) {
                mvwprintw(filter_window, 7, 2, "Error: Valor del filtro demasiado largo");
                wrefresh(filter_window);
                sleep(2);
                filters[0] = '\0';
                nFiltroActivo = 0;
                break;
            }
            nFiltroActivo = 2;
            break;
        case '3':
            if (snprintf(filters, FILTER_BUFFER_SIZE, "%s", filter_value) >= FILTER_BUFFER_SIZE) {
                mvwprintw(filter_window, 7, 2, "Error: Valor del filtro demasiado largo");
                wrefresh(filter_window);
                sleep(2);
                filters[0] = '\0';
                nFiltroActivo = 0;
                break;
            }
            nFiltroActivo = 3;
            break;
        case '4':
            if (snprintf(filters, FILTER_BUFFER_SIZE, "src port %s", filter_value) >= FILTER_BUFFER_SIZE) {
                mvwprintw(filter_window, 7, 2, "Error: Valor del filtro demasiado largo");
                wrefresh(filter_window);
                sleep(2);
                filters[0] = '\0';
                nFiltroActivo = 0;
                break;
            }
            nFiltroActivo = 4;
            break;

    }
            
            noecho();
            curs_set(0);
            break;
        }
    }
    
    // Limpiar y eliminar ventana de filtros
    werase(filter_window);
    wrefresh(filter_window);
    delwin(filter_window);
    
    // Redibujar ventanas principales
    touchwin(main_window);
    touchwin(packet_window);
    wrefresh(main_window);
    wrefresh(packet_window);
}

// Manejador de señal para SIGINT (Ctrl+C)
void signal_handler(int sig) {
    if (capdev) {
        pcap_breakloop(capdev);
        pcap_close(capdev);
    }
    cleanup();
    exit(0);
}

// Función para imprimir información de paquetes en la ventana
void print_packet_info(const char* format, ...) {
    char buffer[1024];
    va_list args;
    
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    wmove(packet_window, current_line, 1);
    wprintw(packet_window, "%s", buffer);
    
    current_line++;
    if (current_line >= WINDOW_HEIGHT - 2) {
        wclear(packet_window);
        box(packet_window, 0, 0);
        current_line = 1;
    }
    
    wrefresh(packet_window);
}

// Función que se va a llamar cada vez que se reciba un paquete
void call_me(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packetd_ptr) {
    packetd_ptr += link_hdr_length;
    struct ip *ip_hdr = (struct ip *)packetd_ptr;
 
    char packet_srcip[INET_ADDRSTRLEN];
    char packet_dstip[INET_ADDRSTRLEN];
    strcpy(packet_srcip, inet_ntoa(ip_hdr->ip_src));
    strcpy(packet_dstip, inet_ntoa(ip_hdr->ip_dst));

    int packet_id = ntohs(ip_hdr->ip_id),
        packet_ttl = ip_hdr->ip_ttl,
        packet_tos = ip_hdr->ip_tos,
        packet_len = ntohs(ip_hdr->ip_len),
        packet_hlen = ip_hdr->ip_hl;

    print_packet_info("ID: %d | SRC: %s | DST: %s", packet_id, packet_srcip, packet_dstip);

    packetd_ptr += (4 * packet_hlen);
    int protocol_type = ip_hdr->ip_p;

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmp *icmp_header;
    int src_port, dst_port;
  
    switch (protocol_type) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)packetd_ptr;
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);
            print_packet_info("PROTO: TCP | FLAGS: %c%c%c | SPORT: %d | DPORT: %d",
                    (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
                    (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
                    (tcp_header->th_flags & TH_URG ? 'U' : '-'),
                    src_port, dst_port);
            break;
    
        case IPPROTO_UDP:
            udp_header = (struct udphdr *)packetd_ptr;
            src_port = ntohs(udp_header->uh_sport);
            dst_port = ntohs(udp_header->uh_dport);
            print_packet_info("PROTO: UDP | SPORT: %d | DPORT: %d", src_port, dst_port);
            break;

        case IPPROTO_ICMP:
            icmp_header = (struct icmp *)packetd_ptr;
            print_packet_info("PROTO: ICMP | TYPE: %d | CODE: %d",
                    icmp_header->icmp_type, icmp_header->icmp_code);
            break;
    }
}

// Función que se ejecutará en el hilo de captura de paquetes
void* capture_thread_function(void* arg) {
    pcap_loop(capdev, -1, call_me, NULL);
    scanning = 0;
    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char const *argv[]) {
    if (!initscr()) {
        fprintf(stderr, "Error inicializando interfaz gráfica\n");
        return 1;
    }

    if (!has_colors()) {
        endwin();
        fprintf(stderr, "Tu terminal no soporta colores\n");
        return 1;
    }

    start_color();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    refresh();

    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_RED, COLOR_BLACK);
    init_pair(3, COLOR_WHITE, COLOR_BLACK);

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    int start_x = (max_x - WINDOW_WIDTH) / 2;
    int start_y = (max_y - (WINDOW_HEIGHT + 5)) / 2;

    //Configurar dimesiones para las secciones
    main_window = newwin(8, WINDOW_WIDTH, start_y, start_x);
    packet_window = newwin(WINDOW_HEIGHT, WINDOW_WIDTH, start_y + 8, start_x);

    if(!main_window || !packet_window){
        cleanup();
        fprintf(stderr,"Error creando las ventanas\n");
        return 1;
    }

    signal(SIGINT, signal_handler);

    char *device = "enp0s3";
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    bpf_u_int32 netmask;


    box(main_window, 0, 0);
    box(packet_window, 0, 0);
    wrefresh(main_window);
    wrefresh(packet_window);

    while (1) {
        werase(main_window);
        box(main_window, 0, 0);
        
        wattron(main_window, COLOR_PAIR(1));
        mvwprintw(main_window, 1, 35, "NETSPY");
        wattroff(main_window, COLOR_PAIR(1));
        
        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 3, 2, "Presione ESPACIO para iniciar/detener la captura | Q para salir");
        wattroff(main_window, COLOR_PAIR(3));

        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 5, 2, "Presione F para configurar filtros");
        wattroff(main_window, COLOR_PAIR(3));

        //Imprimir cual es el filtro está activo
        switch(nFiltroActivo){
            case 0:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "No hay filtros activos");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 1:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro Activo: Source IP");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 2:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro Activo: Destination IP");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 3:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro activo: Protocolo");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 4:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro Activo: Source Port");
                wattroff(main_window, COLOR_PAIR(3));
                break;
        }

        //Apagar Filtro Activo
        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 6, 2, "Presione N para desactivar filtro activo");
        wattroff(main_window, COLOR_PAIR(3));            
                

        if (scanning) {
            wattron(main_window, COLOR_PAIR(1));
            mvwprintw(main_window, 2, 2, "Estado: Capturando paquetes...");
            wattroff(main_window, COLOR_PAIR(1));
        } else {
            wattron(main_window, COLOR_PAIR(2));
            mvwprintw(main_window, 2, 2, "Estado: Esperando inicio de captura");
            wattroff(main_window, COLOR_PAIR(2));
        }
        
        wrefresh(main_window);
        box(packet_window, 0, 0);
        wrefresh(packet_window);

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            if (scanning && capdev) {
                pcap_breakloop(capdev);
                pthread_join(capture_thread, NULL);
                pcap_close(capdev);
            }
            break;
        } else if (ch=='N' || ch=='n'){
                //Parar loop de captura e hilo
            if(scanning && capdev){
                pcap_breakloop(capdev);
                pthread_join(capture_thread, NULL);
            }
             //Vaciar filters
             memset(filters, 0, FILTER_BUFFER_SIZE);
             //Estblecer en 0 nFiltroActivo
             nFiltroActivo = 0;               
                
        } else if (ch == 'F' || ch == 'f') {
            showFilterConfig();        
              
            // Si hay una captura activa, reiniciarla para aplicar el nuevo filtro
            if (scanning && capdev) {
                pcap_breakloop(capdev);
                pthread_join(capture_thread, NULL);
                pcap_close(capdev);
                capdev = NULL;
                scanning = 0;
            }
        } else if (ch == ' ') {
            if (!scanning) {
                werase(main_window);
                box(main_window, 0, 0);
                wrefresh(main_window);

                capdev = pcap_open_live(device, BUFSIZ, 0, -1, error_buffer);
                if (capdev == NULL) {
                    wattron(main_window, COLOR_PAIR(2));
                    mvwprintw(main_window, 2, 2, "Error: %s", error_buffer);
                    wattroff(main_window, COLOR_PAIR(2));
                    wrefresh(main_window);
                    continue;
                }

                int link_hdr_type = pcap_datalink(capdev);
                switch (link_hdr_type) {
                    case DLT_NULL:
                        link_hdr_length = 4;
                        break;
                    case DLT_EN10MB:
                        link_hdr_length = 14;
                        break;
                    default:
                        link_hdr_length = 0;
                }

                if (pcap_compile(capdev, &bpf, filters, 0, netmask) == PCAP_ERROR) {
                    wattron(main_window, COLOR_PAIR(2));
                    mvwprintw(main_window, 2, 2, "Error compiling filter");
                    wattroff(main_window, COLOR_PAIR(2));
                    wrefresh(main_window);
                    continue;
                }

                if (pcap_setfilter(capdev, &bpf)) {
                    wattron(main_window, COLOR_PAIR(2));
                    mvwprintw(main_window, 2, 2, "Error setting filter");
                    wattroff(main_window, COLOR_PAIR(2));
                    wrefresh(main_window);
                    continue;
                }

                scanning = 1;
                werase(main_window);
                box(main_window, 0, 0);
                wattron(main_window, COLOR_PAIR(1));
                mvwprintw(main_window, 1, 35, "NETSPY");
                mvwprintw(main_window, 2, 2, "Estado: Capturando paquetes...");
                wattroff(main_window, COLOR_PAIR(1));
                wrefresh(main_window);

                // Crear hilo para la captura
                if (pthread_create(&capture_thread, NULL, capture_thread_function, NULL) != 0) {
                    wattron(main_window, COLOR_PAIR(2));
                    mvwprintw(main_window, 2, 2, "Error creating capture thread");
                    wattroff(main_window, COLOR_PAIR(2));
                    wrefresh(main_window);
                    scanning = 0;
                    continue;
                }
            } else {
                if (capdev) {
                    pcap_breakloop(capdev);
                    pthread_join(capture_thread, NULL);
                    pcap_close(capdev);
                    capdev = NULL;
                }
                scanning = 0;

                werase(main_window);
                box(main_window, 0, 0);
                wattron(main_window, COLOR_PAIR(2));
                mvwprintw(main_window, 2, 2, "Estado: Esperando inicio de captura");
                wattroff(main_window, COLOR_PAIR(2));
                wrefresh(main_window);
            }
        }
    }

    cleanup();
    return 0;
}



