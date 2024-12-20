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
#include <ncurses.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#define MAX_PACKET_SIZE 65535 //El tamaño máximo de un paquete
#define RAW_DATA_DISPLAY_BYTES 160  // Número de bytes para mostrar en la ventana RAW

// Definir la estructura de cada paquete
typedef struct Packet {
    char id[5];
    char ttl[4];
    char tos[4];
    char len[4];
    char hlen[4];
    char sourceIP[16];
    char destIP[16];
    char protocol[16];
    char sourcePort[8];
    char destPort[8];
    int idUnicoPacket;
    u_char raw_data[MAX_PACKET_SIZE];
    int raw_data_len;
    struct Packet *next; // Puntero al siguiente nodo
} Packet;

Packet *packetList = NULL; // Inicializa la lista de paquetes vacía

//Constantes para la interfaz gráfica
#define WINDOW_HEIGHT 30
#define WINDOW_WIDTH 140
#define START_Y 2
#define START_X 2
#define FILTER_BUFFER_SIZE 512  // Aumentamos el tamaño del buffer

WINDOW *main_window;          //Ventana de opciones
WINDOW *packet_window;        //Ventana de información de paquetes
WINDOW *filter_window;        // Ventana para la configuración de filtros
WINDOW *struct_window;        //Ventana de info. estructurada del paquete selccionado
WINDOW *raw_window;           //Ventana de info. RAW del paquete seleccionado  
int current_line = 1;
int scanning = 0;
int link_hdr_length = 0;
pcap_t *capdev = NULL;
pthread_t capture_thread;
int nFiltroActivo=0; //Variable para saber que filtro está activo, 1=SRC IP, 2=DST IP, 3=Protocolo, 4=Source Port
char filters[FILTER_BUFFER_SIZE] = ""; //Para almacenar que filtro se va a ocupar
char filter_value[FILTER_BUFFER_SIZE] = ""; //Para almacenar el valor del filtro que se va a ocupar
int conteoPackets=1; //Contabilizar cuantos packets detectados van
Packet *packets;
int packetLeer=0;


// Función para limpiar y cerrar ncurses apropiadamente
void cleanup() {
    if (main_window) delwin(main_window);
    if (packet_window) delwin(packet_window);
    endwin();
}

void addPacket(Packet **head, char *id, char *sourceIP, char *destIP, char *protocol, 
               char *sourcePort, char *destPort, char *ttl, char *tos, 
               char *len, char *hlen, const u_char *raw_data, int raw_data_len) {
    // Crear un nuevo nodo
    Packet *newNode = (Packet *)malloc(sizeof(Packet));
    if (newNode == NULL) {
        perror("Error al asignar memoria");
        exit(1);
    }

    // Llenar el nodo con los datos
    strncpy(newNode->id, id, sizeof(newNode->id) - 1);
    newNode->id[sizeof(newNode->id) - 1] = '\0';

    strncpy(newNode->sourceIP, sourceIP, sizeof(newNode->sourceIP) - 1);
    newNode->sourceIP[sizeof(newNode->sourceIP) - 1] = '\0';

    strncpy(newNode->destIP, destIP, sizeof(newNode->destIP) - 1);
    newNode->destIP[sizeof(newNode->destIP) - 1] = '\0';

    strncpy(newNode->protocol, protocol, sizeof(newNode->protocol) - 1);
    newNode->protocol[sizeof(newNode->protocol) - 1] = '\0';

    strncpy(newNode->sourcePort, sourcePort, sizeof(newNode->sourcePort) - 1);
    newNode->sourcePort[sizeof(newNode->sourcePort) - 1] = '\0';

    strncpy(newNode->destPort, destPort, sizeof(newNode->destPort) - 1);
    newNode->destPort[sizeof(newNode->destPort) - 1] = '\0';

    strncpy(newNode->ttl, ttl, sizeof(newNode->ttl) - 1);
    newNode->ttl[sizeof(newNode->ttl) - 1] = '\0';

    strncpy(newNode->tos, tos, sizeof(newNode->tos) - 1);
    newNode->tos[sizeof(newNode->tos) - 1] = '\0';

    strncpy(newNode->len, len, sizeof(newNode->len) - 1);
    newNode->len[sizeof(newNode->len) - 1] = '\0';

    strncpy(newNode->hlen, hlen, sizeof(newNode->hlen) - 1);
    newNode->hlen[sizeof(newNode->hlen) - 1] = '\0';

    newNode->idUnicoPacket=conteoPackets;
    newNode->next = NULL;

    // Copiar datos RAW
    memcpy(newNode->raw_data, raw_data, raw_data_len); //Mover a raw_data del nodo la variable raw_data, hasta la cantidad que raw_data_len diga
    newNode->raw_data_len = raw_data_len; //Mover el raw_data_len al nodo

    conteoPackets++;

    // Si la lista está vacía, este nodo se convierte en la cabeza
    if (*head == NULL) {
        *head = newNode;
    } else {
        // Encontrar el último nodo de la lista
        Packet *temp = *head;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = newNode;
    }
}

// Liberar memoria de la lista
void freePackets(Packet *head) {
    while (head != NULL) {
        Packet *temp = head;
        head = head->next;
        free(temp);
    }
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
    mvwprintw(filter_window, 5, 2, "3. Filtrar por protocolo (tcp/udp/icmp) (USAR MINUSCULAS)");
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
            //Se ejecuta la sentencia de asignar el filtro a la cadena de filters, si no se puede se manda error de buffer
            if (snprintf(filters, FILTER_BUFFER_SIZE, "src host %s", filter_value) >= FILTER_BUFFER_SIZE) {
                // Manejar error de buffer insuficiente
                mvwprintw(filter_window, 7, 2, "Error: Valor del filtro demasiado largo");
                wrefresh(filter_window);
                sleep(2);
                filters[0] = '\0';  // Limpiar el buffer
                nFiltroActivo = 0;
                break;
            }
            wclear(packet_window);           // Limpia la ventana
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
            wclear(packet_window);           // Limpia la ventana
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
            wclear(packet_window);           // Limpia la ventana
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
            wclear(packet_window);           // Limpia la ventana
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
    
    // Redibujar las demás ventanas
    touchwin(main_window);
    touchwin(packet_window);
    touchwin(raw_window);
    touchwin(struct_window);
    wrefresh(main_window);
    wrefresh(packet_window);
    wrefresh(raw_window);
    wrefresh(struct_window);

    //Reiniciar la linea de texto para los paquetes
    current_line=1;
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

// Función para imprimir información de paquetes en la ventana packets
void print_packet_info(const char* format, ...) {
    char buffer[1024];
    va_list args;

    // Formatea el mensaje a imprimir
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Imprime la información del paquete
    wmove(packet_window, current_line, 1);
    wprintw(packet_window, "%s", buffer);
    current_line++;

    // Verifica si se alcanzó el final de la ventana
    if (current_line >= WINDOW_HEIGHT - 2) {
        wclear(packet_window);           // Limpia la ventana
        box(packet_window, 0, 0);       // Redibuja el borde
        current_line = 1;               // Reinicia la línea actual
    }

    // Refresca la ventana para mostrar los cambios
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

    print_packet_info("IDUnico: %d | SRC: %s | DST: %s", conteoPackets, packet_srcip, packet_dstip);

    packetd_ptr += (4 * packet_hlen);
    int protocol_type = ip_hdr->ip_p;

    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmp *icmp_header;
    int src_port = 0, dst_port = 0;
    char *proto_str = "DESCONOCIDO";
  
    switch (protocol_type) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)packetd_ptr;
            src_port = ntohs(tcp_header->th_sport);
            dst_port = ntohs(tcp_header->th_dport);
            proto_str = "TCP";
            /*print_packet_info("PROTO: TCP | FLAGS: %c%c%c | SPORT: %d | DPORT: %d",
                    (tcp_header->th_flags & TH_SYN ? 'S' : '-'),
                    (tcp_header->th_flags & TH_ACK ? 'A' : '-'),
                    (tcp_header->th_flags & TH_URG ? 'U' : '-'),
                    src_port, dst_port);*/
            break;
    
        case IPPROTO_UDP:
            udp_header = (struct udphdr *)packetd_ptr;
            src_port = ntohs(udp_header->uh_sport);
            dst_port = ntohs(udp_header->uh_dport);
            proto_str = "UDP";
            /*print_packet_info("PROTO: UDP | SPORT: %d | DPORT: %d", src_port, dst_port);*/
            break;

        case IPPROTO_ICMP:
            icmp_header = (struct icmp *)packetd_ptr;
            proto_str = "ICMP";
           /* print_packet_info("PROTO: ICMP | TYPE: %d | CODE: %d",
                    icmp_header->icmp_type, icmp_header->icmp_code);*/
            break;
    }

    // Convertir puertos a cadenas
    char str_src_port[8], str_dst_port[8];
    snprintf(str_src_port, sizeof(str_src_port), "%d", src_port);
    snprintf(str_dst_port, sizeof(str_dst_port), "%d", dst_port);

    //Convertir a cadenas id, ttl, tos, len y hlen
    char str_id[8], str_ttl[8],str_tos[8],str_len[8],str_hlen[8];
    snprintf(str_id, sizeof(str_id), "%d", packet_id);
    snprintf(str_ttl, sizeof(str_ttl), "%d", packet_ttl);
    snprintf(str_tos, sizeof(str_tos), "%d", packet_tos);
    snprintf(str_len, sizeof(str_len), "%d", packet_len);
    snprintf(str_hlen, sizeof(str_hlen), "%d", packet_hlen);

    // Añadir el paquete a la lista
    addPacket(&packetList, str_id, packet_srcip, packet_dstip, 
              proto_str, str_src_port, str_dst_port, str_ttl, str_tos, 
              str_len, str_hlen, packetd_ptr, pkthdr->len);
    
    // Añadir línea separadora después de cada paquete completo
    if (current_line < WINDOW_HEIGHT - 2) {
        wmove(packet_window, current_line, 1);
        wprintw(packet_window, "----------------------");
        current_line++;
        wrefresh(packet_window);
    }
}

// Función para mostrar datos RAW en hexadecimal y ASCII
void display_raw_packet(WINDOW *raw_window, Packet *packet) {
    wclear(raw_window);
    box(raw_window, 0, 0);
    
    mvwprintw(raw_window, 1, 2, "Datos RAW del Paquete %d (Protocolo: %s)", 
              packet->idUnicoPacket, packet->protocol);
    
    // Limitar a MAX_PACKET_SIZE o RAW_DATA_DISPLAY_BYTES
    int display_len = packet->raw_data_len < RAW_DATA_DISPLAY_BYTES ? 
                      packet->raw_data_len : RAW_DATA_DISPLAY_BYTES;
    
    // Mostrar datos en formato hexadecimal
    for (int i = 0; i < display_len; i += 16) {
        // Imprimir offset
        mvwprintw(raw_window, 3 + i/16, 2, "%04x: ", i);
        
        // Imprimir bytes en hexadecimal
        for (int j = 0; j < 16 && (i + j) < display_len; j++) {
            wprintw(raw_window, "%02x ", packet->raw_data[i + j]);
        }
        
        // Imprimir representación ASCII
        mvwprintw(raw_window, 3 + i/16, 55, "  ");
        for (int j = 0; j < 16 && (i + j) < display_len; j++) {
            unsigned char c = packet->raw_data[i + j];
            wprintw(raw_window, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
    }
    
    // Información adicional
    mvwprintw(raw_window, WINDOW_HEIGHT/2 - 2, 2, 
              "Longitud total del paquete: %d bytes", packet->raw_data_len);
    
    wrefresh(raw_window);
}


// Función que se ejecutará en el hilo de captura de paquetes
void* capture_thread_function(void* arg) {
    pcap_loop(capdev, -1, call_me, NULL);
    scanning = 0;
    pthread_exit(NULL);
    return NULL;
}

//Función para exportar los resultados a un archivo CSV
void export_to_csv() {

    FILE *csv_file = NULL;
    char csv_path[256];

    snprintf(csv_path, sizeof(csv_path), "netspy_packets_%ld.csv", time(NULL));
    csv_file = fopen(csv_path, "w");

    if (csv_file == NULL) {
        // Si no se puede crear el archivo, mostrar un error
        wclear(struct_window);
        box(struct_window, 0, 0);
        mvwprintw(struct_window, 1, 2, "Error: Cannot create CSV file");
        wrefresh(struct_window);
        return;
    }

    // Escribir el header del archivo
    fprintf(csv_file, "ID,IP Origen,IP Destino,Protocolo,Puerto Origen,Puerto Destino,TTL,TOS,Longitud,Longitud de Encabezado\n");

    // Escribir los datos de cada nodo en el archivo CSV
    Packet *current = packetList;
    while (current != NULL) {
        fprintf(csv_file, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
                current->id, 
                current->sourceIP, 
                current->destIP, 
                current->protocol, 
                current->sourcePort, 
                current->destPort,
                current->ttl,
                current->tos,
                current->len,
                current->hlen);
        current = current->next;
    }

    // Cerrar el archivo
    fclose(csv_file);

    // Mostrar mensaje de éxito en la pantalla de struct
    wclear(struct_window);
    box(struct_window, 0, 0);
    mvwprintw(struct_window, 1, 2, "Exportado a: %s", csv_path);
    wrefresh(struct_window);
}

int main(int argc, char const *argv[]) {

    if (!initscr()) {
        fprintf(stderr, "Error inicializando ncurses!\n");
        return 1;
    }

    // Check terminal capabilities
    if (!has_colors()) {
        endwin();
        fprintf(stderr, "Tu terminal no soporta colores!\n");
        return 1;
    }

    // Obtener dimesiones de la ventana de la terminal usada
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    // Checar si la terminal es de las dimensiones incorrectas
    if (max_y < WINDOW_HEIGHT + 10 || max_x < WINDOW_WIDTH) {
        endwin();
        fprintf(stderr, "La terminal es muy pequeña, debe ser de:  %d x %d\n", 
                WINDOW_WIDTH, WINDOW_HEIGHT + 10);
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

    int start_x = (max_x - WINDOW_WIDTH) / 2;
    int start_y = (max_y - (WINDOW_HEIGHT + 10)) / 2;

    //Creación de ventanas 
    main_window = newwin(10, WINDOW_WIDTH, start_y, start_x);
    if (!main_window) {
        endwin();
        fprintf(stderr, "Error al crear ventana principal\n");
        return 1;
    }

    packet_window = newwin(WINDOW_HEIGHT, (WINDOW_WIDTH/2)-5, start_y + 10, start_x);
    if (!packet_window) {
        delwin(main_window);
        endwin();
        fprintf(stderr, "Error al crear la ventana de packets\n");
        return 1;
    }

    struct_window=newwin(WINDOW_HEIGHT/2,(WINDOW_WIDTH/2)+5,start_y+10,start_x+65);
    if (!struct_window) {
        delwin(main_window);
        endwin();
        fprintf(stderr, "Error al crear la ventana de estructura de paquetes\n");
        return 1;
    }

    raw_window=newwin(WINDOW_HEIGHT/2,(WINDOW_WIDTH/2)+5,start_y+25,start_x+65);
    if (!raw_window) {
        delwin(main_window);
        endwin();
        fprintf(stderr, "Error al crear la ventana RAW\n");
        return 1;
    }

    signal(SIGINT, signal_handler);

    char *device = "enp0s3";
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    bpf_u_int32 netmask;


    box(main_window, 0, 0);
    box(packet_window, 0, 0);
    box(struct_window,0,0);
    box(raw_window,0,0);
    wrefresh(main_window);
    wrefresh(packet_window);
    wrefresh(struct_window);
    wrefresh(raw_window);

    while (1) {
        werase(main_window);
        box(main_window, 0, 0);
        wattron(main_window, COLOR_PAIR(1));
        mvwprintw(main_window, 1, 62, "NETSPY");
        wattroff(main_window, COLOR_PAIR(1));
        
        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 3, 2, "Presione ESPACIO para iniciar/detener la captura | Q para salir");
        wattroff(main_window, COLOR_PAIR(3));

        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 5, 2, "Presione F para configurar filtros | N para desactivar filtro activo");
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
                mvwprintw(main_window, 4, 2, "Filtro Activo: IP Origen");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 2:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro Activo: IP Destino");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 3:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro activo: Protocolo");
                wattroff(main_window, COLOR_PAIR(3));
                break;
            case 4:
                wattron(main_window, COLOR_PAIR(3));
                mvwprintw(main_window, 4, 2, "Filtro Activo: Puerto Origen");
                wattroff(main_window, COLOR_PAIR(3));
                break;
        }        
                
        //Texto seleccionar paquete
        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 6, 2, "Presione P para seleccionar un paquete");
        wattroff(main_window, COLOR_PAIR(3));  

        //Texto exportar resultados
        wattron(main_window, COLOR_PAIR(3));
        mvwprintw(main_window, 7, 2, "Presione X para exportar resultados a un archivo CSV en la ruta del programa");
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
             //Vaciar filtros
             memset(filters, 0, FILTER_BUFFER_SIZE);
             //Estblecer en 0 nFiltroActivo
             nFiltroActivo = 0;    

        } else if (ch=='P' || ch=='p'){
            //Parar loop de captura e hilo
            if(scanning && capdev){
                pcap_breakloop(capdev);
                pthread_join(capture_thread, NULL);
            }
            
            // Limpiar línea de entrada
            wmove(main_window, 8, 2);
            wclrtoeol(main_window);
            box(main_window, 0, 0);
            
            // Solicitar valor del packet
            echo();
            curs_set(1);
            wmove(main_window, 8, 2);
            wprintw(main_window, "Ingrese numero de packet a examinar: ");
            wrefresh(main_window);

            // Leer valor del packet como str
            char packet_input[20];
            wgetnstr(main_window, packet_input, sizeof(packet_input)-1);
            
            // Convertir el input a entero
            int selected_packet = atoi(packet_input);
            
            // Buscar el paquete en la lista
            Packet *current = packetList;
            while (current != NULL) {
                if (current->idUnicoPacket == selected_packet) {
                    // Mostrar detalles del paquete en la ventana struct
                    wclear(struct_window);
                    box(struct_window, 0, 0);
                    mvwprintw(struct_window, 1, 2, "Detalles del Paquete %d:", selected_packet);
                    mvwprintw(struct_window, 3, 2, "ID: %s", current->id);
                    mvwprintw(struct_window, 4, 2, "IP Origen: %s", current->sourceIP);
                    mvwprintw(struct_window, 5, 2, "IP Destino: %s", current->destIP);
                    mvwprintw(struct_window, 6, 2, "Protocolo: %s", current->protocol);
                    mvwprintw(struct_window, 7, 2, "Puerto Origen: %s", current->sourcePort);
                    mvwprintw(struct_window, 8, 2, "Puerto Destino: %s", current->destPort);
                    mvwprintw(struct_window, 9, 2, "TTL: %s", current->ttl); 
                    mvwprintw(struct_window, 10, 2, "TOS: %s", current->tos);    
                    mvwprintw(struct_window, 11, 2, "Length: %s", current->len);               
                    mvwprintw(struct_window, 12, 2, "Header length: %s", current->hlen);              
                    wrefresh(struct_window);

                    if (current != NULL) {
                        // Mostrar datos RAW en raw_window
                        display_raw_packet(raw_window, current);
                    }
                                
                    break;
                }
                current = current->next;
            }
            
            // Si no se encuentra el paquete
            if (current == NULL) {
                wclear(struct_window);
                box(struct_window, 0, 0);
                mvwprintw(struct_window, 1, 2, "Paquete %d no encontrado", selected_packet);
                wrefresh(struct_window);

                // Mostrar mensaje de error RAW en raw_window
                wclear(raw_window);
                box(raw_window, 0, 0);
                mvwprintw(raw_window, 1, 2, "Paquete %d no encontrado", selected_packet);      
                wrefresh(raw_window);    
            }
            
            // Restaurar configuración de pantalla
            noecho();
            curs_set(0);
            wrefresh(main_window);
                                             
                
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

        } else if (ch=='X' || ch=='x'){

             // Pausar captura
            if (scanning && capdev) {
                pcap_breakloop(capdev);
                pthread_join(capture_thread, NULL);
            }
            
            // Exportar a CSV
            export_to_csv();           


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



