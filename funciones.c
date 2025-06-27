#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "seguridad.h"

int cargar_log(const char *ruta, LogEntry logs[]) {
    FILE *f = fopen(ruta, "r");
    if (!f) return -1;
    int count = 0;
    char line[512];
    while (count < MAX_ENTRIES && fgets(line, sizeof(line), f)) {
        char *p = line;
        char *dash = strstr(p, " - ");
        if (!dash) continue;
        size_t tslen = dash - p;
        strncpy(logs[count].timestamp, p, tslen);
        logs[count].timestamp[tslen] = '\0';
        p = dash + 3;
        
        /* Buscar IP */
        char *ip_start = strstr(p, "IP: ");
        if (!ip_start) continue;
        ip_start += 4;
        char *ip_end = strstr(ip_start, " - ");
        if (!ip_end) continue;
        size_t ip_len = ip_end - ip_start;
        strncpy(logs[count].ip, ip_start, ip_len);
        logs[count].ip[ip_len] = '\0';
        
        /* Buscar User */
        char *user_start = strstr(ip_end, "User: ");
        if (!user_start) continue;
        user_start += 6;
        char *user_end = strstr(user_start, " - ");
        if (!user_end) continue;
        size_t user_len = user_end - user_start;
        strncpy(logs[count].user, user_start, user_len);
        logs[count].user[user_len] = '\0';
        
        /* Buscar Status */
        char *status_start = strstr(user_end, "Status: ");
        if (!status_start) continue;
        status_start += 8;
        char *status_end = strchr(status_start, '\n');
        if (!status_end) status_end = strchr(status_start, '\r');
        if (!status_end) status_end = status_start + strlen(status_start);
        size_t status_len = status_end - status_start;
        strncpy(logs[count].status, status_start, status_len);
        logs[count].status[status_len] = '\0';
        
        count++;
    }
    fclose(f);
    return count;
}

int es_usuario_privilegiado(const char *username) {
    // Lista de usuarios privilegiados comunes
    const char *privileged_users[] = {
        "admin", "administrator", "root", "sa", "sysadmin", 
        "superuser", "postgres", "mysql", "oracle", "sys",
        "system", "service", "daemon", "wheel", "sudo",
        "operator", "manager", "supervisor", "executive",
        "director", "owner", "master", "chief", NULL
    };
    
    // Convertir a minúsculas para comparación
    char lower_username[MAX_LEN];
    strncpy(lower_username, username, MAX_LEN - 1);
    lower_username[MAX_LEN - 1] = '\0';
    
    for (int i = 0; lower_username[i]; i++) {
        if (lower_username[i] >= 'A' && lower_username[i] <= 'Z') {
            lower_username[i] = lower_username[i] + 32; // convertir a minúscula
        }
    }
    
    // Verificar si está en la lista
    for (int i = 0; privileged_users[i] != NULL; i++) {
        if (strcmp(lower_username, privileged_users[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
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
            ips[idx].last_failed_user[0] = '\0';
            ips[idx].is_privileged_attempt = 0;
        }
        if (idx < 0) continue;
        
        /* si bloqueada, saltar */
        if (ips[idx].blocked_until > now) continue;
        
        /* verificar si es usuario privilegiado */
        int is_privileged = es_usuario_privilegiado(logs[i].user);
        
        /* actualizar información del último intento */
        strncpy(ips[idx].last_failed_user, logs[i].user, MAX_LEN - 1);
        ips[idx].last_failed_user[MAX_LEN - 1] = '\0';
        ips[idx].is_privileged_attempt = is_privileged;
        
        ips[idx].fails++;
        
        /* determinar umbral según tipo de usuario */
        int threshold = is_privileged ? PRIVILEGED_FAIL_THRESHOLD : FAIL_THRESHOLD;
        
        if (ips[idx].fails >= threshold) {
            ips[idx].blocked_until = now + BLOCK_DURATION;
            printf("ALERTA: IP %s bloqueada por %d intentos fallidos con usuario %s%s\n",
                   ips[idx].ip, ips[idx].fails, logs[i].user,
                   is_privileged ? " (PRIVILEGIADO)" : "");
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
    int bloqueadas = 0;
    int con_fallos = 0;
    int privilegiados_bloqueados = 0;
    
    printf("\n=== ESTADO DE IPs ===\n");
    
    // Contar IPs bloqueadas y con fallos
    for (int i = 0; i < nips; i++) {
        if (ips[i].blocked_until > now) {
            bloqueadas++;
            if (ips[i].is_privileged_attempt) {
                privilegiados_bloqueados++;
            }
        }
        if (ips[i].fails > 0) {
            con_fallos++;
        }
    }
    
    printf("Total de IPs monitoreadas: %d\n", nips);
    printf("IPs actualmente bloqueadas: %d\n", bloqueadas);
    printf("  - Por intentos con usuarios privilegiados: %d\n", privilegiados_bloqueados);
    printf("IPs con intentos fallidos: %d\n\n", con_fallos);
    
    if (bloqueadas > 0) {
        printf("IPs BLOQUEADAS:\n");
        for (int i = 0; i < nips; i++) {
            if (ips[i].blocked_until > now) {
                char *time_str = ctime(&ips[i].blocked_until);
                time_str[strlen(time_str)-1] = '\0'; // Remover \n
                
                const char *tipo = ips[i].is_privileged_attempt ? "PRIVILEGIADO" : "NORMAL";
                int threshold = ips[i].is_privileged_attempt ? PRIVILEGED_FAIL_THRESHOLD : FAIL_THRESHOLD;
                
                printf("- %s (%d fallos, umbral=%d, tipo=%s)\n",
                       ips[i].ip, ips[i].fails, threshold, tipo);
                printf("  Último usuario: %s, bloqueada hasta %s\n",
                       ips[i].last_failed_user, time_str);
            }
        }
    }
    
    if (con_fallos > bloqueadas) {
        printf("\nIPs CON FALLOS (no bloqueadas aún):\n");
        for (int i = 0; i < nips; i++) {
            if (ips[i].fails > 0 && ips[i].blocked_until <= now) {
                int threshold = ips[i].is_privileged_attempt ? PRIVILEGED_FAIL_THRESHOLD : FAIL_THRESHOLD;
                const char *tipo = ips[i].is_privileged_attempt ? " (PRIVILEGIADO)" : "";
                
                printf("- %s (%d fallos de %d permitidos%s)\n",
                       ips[i].ip, ips[i].fails, threshold, tipo);
                printf("  Último usuario: %s\n", ips[i].last_failed_user);
            }
        }
    }
    
    if (nips == 0) {
        printf("No hay IPs registradas aún.\n");
    }
}

int guardar_estado_ips(const char *ruta, const IPInfo ips[], int nips) {
    FILE *f = fopen(ruta, "w");
    if (!f) {
        printf("Error: No se puede crear el archivo de estado '%s'\n", ruta);
        return -1;
    }
    
    // Escribir número de IPs
    fprintf(f, "%d\n", nips);
    
    // Escribir cada IP con sus datos (formato ampliado)
    for (int i = 0; i < nips; i++) {
        fprintf(f, "%s %d %ld %s %d\n", 
                ips[i].ip, 
                ips[i].fails, 
                (long)ips[i].blocked_until,
                ips[i].last_failed_user,
                ips[i].is_privileged_attempt);
    }
    
    fclose(f);
    printf("Estado guardado: %d IPs en '%s'\n", nips, ruta);
    return 0;
}

int cargar_estado_ips(const char *ruta, IPInfo ips[], int *nips) {
    FILE *f = fopen(ruta, "r");
    if (!f) {
        printf("No se encontró archivo de estado previo '%s' (primera ejecución)\n", ruta);
        *nips = 0;
        return 0; // No es error, solo primera ejecución
    }
    
    int count;
    if (fscanf(f, "%d", &count) != 1) {
        printf("Error: Archivo de estado corrupto\n");
        fclose(f);
        *nips = 0;
        return -1;
    }
    
    if (count > MAX_UNIQUE_IPS) {
        printf("Advertencia: El archivo tiene %d IPs, limitando a %d\n", 
               count, MAX_UNIQUE_IPS);
        count = MAX_UNIQUE_IPS;
    }
    
    time_t now = time(NULL);
    int loaded = 0;
    
    for (int i = 0; i < count; i++) {
        char ip[MAX_LEN];
        char last_user[MAX_LEN];
        int fails;
        long blocked_until;
        int is_privileged;
        
        // Intentar leer formato nuevo primero
        int fields_read = fscanf(f, "%127s %d %ld %127s %d", 
                                ip, &fails, &blocked_until, last_user, &is_privileged);
        
        if (fields_read == 5) {
            // Formato nuevo con todos los campos
        } else if (fields_read == 3) {
            // Formato antiguo, establecer valores por defecto
            strcpy(last_user, "unknown");
            is_privileged = 0;
        } else {
            // Error de formato
            continue;
        }
        
        // Solo cargar IPs que aún están bloqueadas o tienen fallos recientes
        if (blocked_until > now || fails > 0) {
            strncpy(ips[loaded].ip, ip, MAX_LEN - 1);
            ips[loaded].ip[MAX_LEN - 1] = '\0';
            ips[loaded].fails = fails;
            ips[loaded].blocked_until = (time_t)blocked_until;
            strncpy(ips[loaded].last_failed_user, last_user, MAX_LEN - 1);
            ips[loaded].last_failed_user[MAX_LEN - 1] = '\0';
            ips[loaded].is_privileged_attempt = is_privileged;
            loaded++;
        }
    }
    
    fclose(f);
    *nips = loaded;
    printf("Estado cargado: %d IPs activas de %d totales\n", loaded, count);
    return loaded;
}
