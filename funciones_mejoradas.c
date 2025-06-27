#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "seguridad.h"

int cargar_log(const char *ruta, LogEntry logs[]) {
    FILE *f = fopen(ruta, "r");
    if (!f) {
        printf("Error: No se puede abrir el archivo '%s'\n", ruta);
        return -1;
    }
    
    int count = 0;
    char line[512];
    
    printf("Archivo abierto correctamente. Procesando líneas...\n");
    
    while (count < MAX_ENTRIES && fgets(line, sizeof(line), f)) {
        // Eliminar salto de línea
        line[strcspn(line, "\r\n")] = '\0';
        
        // Buscar el primer " - " para separar timestamp
        char *first_dash = strstr(line, " - ");
        if (!first_dash) {
            printf("Línea ignorada (no tiene formato correcto): %.50s...\n", line);
            continue;
        }
        
        // Extraer timestamp
        size_t ts_len = first_dash - line;
        if (ts_len >= MAX_LEN) ts_len = MAX_LEN - 1;
        strncpy(logs[count].timestamp, line, ts_len);
        logs[count].timestamp[ts_len] = '\0';
        
        // Buscar "IP: "
        char *ip_start = strstr(first_dash, "IP: ");
        if (!ip_start) {
            printf("Línea ignorada (no tiene IP): %.50s...\n", line);
            continue;
        }
        ip_start += 4; // saltar "IP: "
        
        // Buscar el siguiente " - " después de IP
        char *ip_end = strstr(ip_start, " - ");
        if (!ip_end) {
            printf("Línea ignorada (IP mal formateada): %.50s...\n", line);
            continue;
        }
        
        // Extraer IP
        size_t ip_len = ip_end - ip_start;
        if (ip_len >= MAX_LEN) ip_len = MAX_LEN - 1;
        strncpy(logs[count].ip, ip_start, ip_len);
        logs[count].ip[ip_len] = '\0';
        
        // Buscar "User: "
        char *user_start = strstr(ip_end, "User: ");
        if (!user_start) {
            printf("Línea ignorada (no tiene User): %.50s...\n", line);
            continue;
        }
        user_start += 6; // saltar "User: "
        
        // Buscar el siguiente " - " después de User
        char *user_end = strstr(user_start, " - ");
        if (!user_end) {
            printf("Línea ignorada (User mal formateado): %.50s...\n", line);
            continue;
        }
        
        // Extraer User
        size_t user_len = user_end - user_start;
        if (user_len >= MAX_LEN) user_len = MAX_LEN - 1;
        strncpy(logs[count].user, user_start, user_len);
        logs[count].user[user_len] = '\0';
        
        // Buscar "Status: "
        char *status_start = strstr(user_end, "Status: ");
        if (!status_start) {
            printf("Línea ignorada (no tiene Status): %.50s...\n", line);
            continue;
        }
        status_start += 8; // saltar "Status: "
        
        // Extraer Status (hasta el final de la línea)
        size_t status_len = strlen(status_start);
        if (status_len >= MAX_LEN) status_len = MAX_LEN - 1;
        strncpy(logs[count].status, status_start, status_len);
        logs[count].status[status_len] = '\0';
        
        count++;
        if (count % 10 == 0) {
            printf("Procesadas %d líneas...\n", count);
        }
    }
    
    fclose(f);
    printf("Total de registros cargados: %d\n", count);
    return count;
}

int analizar_intentos(const LogEntry logs[], int nlogs,
                       IPInfo ips[], int *nips) {
    int unique = 0;
    time_t now = time(NULL);
    for (int i = 0; i < nlogs; i++) {
        if (strcmp(logs[i].status, "FAILED") != 0) continue;
        /* localizar o agregar IP */
        int idx = -1;
        for (int j = 0; j < unique; j++) {
            if (strcmp(ips[j].ip, logs[i].ip) == 0) { idx = j; break; }
        }
        if (idx < 0 && unique < MAX_UNIQUE_IPS) {
            idx = unique++;
            strncpy(ips[idx].ip, logs[i].ip, MAX_LEN);
            ips[idx].fails = 0;
            ips[idx].blocked_until = 0;
        }
        if (idx < 0) continue;
        /* si bloqueada, saltar */
        if (ips[idx].blocked_until > now) continue;
        ips[idx].fails++;
        if (ips[idx].fails >= FAIL_THRESHOLD) {
            ips[idx].blocked_until = now + BLOCK_DURATION;
        }
    }
    *nips = unique;
    return unique;
}

void guardar_fallidos(const char *ruta,
                      const LogEntry logs[], int nlogs,
                      const IPInfo ips[], int nips) {
    FILE *f = fopen(ruta, "w");
    if (!f) return;
    for (int i = 0; i < nips; i++) {
        if (ips[i].blocked_until == 0) continue;
        fprintf(f, "# IP BLOQUEADA: %s hasta %s\n",
                ips[i].ip,
                ctime(&ips[i].blocked_until));
        for (int j = 0; j < nlogs; j++) {
            if (strcmp(logs[j].ip, ips[i].ip) == 0 &&
                strcmp(logs[j].status, "FAILED") == 0) {
                fprintf(f,
                        "%s - IP: %s - User: %s - Status: %s\n",
                        logs[j].timestamp,
                        logs[j].ip,
                        logs[j].user,
                        logs[j].status);
            }
        }
        fprintf(f, "\n");
    }
    fclose(f);
}

void mostrar_bloqueados(const IPInfo ips[], int nips) {
    time_t now = time(NULL);
    printf("\nIPs bloqueadas (>=%d fallos):\n", FAIL_THRESHOLD);
    for (int i = 0; i < nips; i++) {
        if (ips[i].blocked_until > now) {
            printf("- %s (hasta %s)",
                   ips[i].ip,
                   ctime(&ips[i].blocked_until));
        }
    }
}
