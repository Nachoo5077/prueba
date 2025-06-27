#ifndef SEGURIDAD_H
#define SEGURIDAD_H

#include <time.h>

#define MAX_ENTRIES      2000
#define MAX_UNIQUE_IPS   200
#define MAX_LEN          128
#define FAIL_THRESHOLD   3
#define PRIVILEGED_FAIL_THRESHOLD  1  /* Solo 1 intento para usuarios privilegiados */
#define BLOCK_DURATION   (2 * 24 * 60 * 60)  /* 2 días en segundos */

/* Registro de cada intento de login */
typedef struct {
    char timestamp[MAX_LEN];   /* "YYYY-MM-DD HH:MM:SS" */
    char ip[MAX_LEN];          /* dirección IP */
    char user[MAX_LEN];        /* nombre de usuario */
    char status[MAX_LEN];      /* "SUCCESS" o "FAILED" */
} LogEntry;

/* Estado por IP */
typedef struct {
    char ip[MAX_LEN];          /* dirección IP */
    int fails;                 /* número de intentos fallidos */
    time_t blocked_until;      /* timestamp fin de bloqueo */
    char last_failed_user[MAX_LEN]; /* último usuario que falló desde esta IP */
    int is_privileged_attempt; /* 1 si el último intento fue de usuario privilegiado */
} IPInfo;

/* Prototipos */
int  cargar_log(const char *ruta, LogEntry logs[]);
int  analizar_intentos(const LogEntry logs[], int nlogs,
                       IPInfo ips[], int *nips);
void guardar_fallidos(const char *ruta,
                      const LogEntry logs[], int nlogs,
                      const IPInfo ips[], int nips);
void mostrar_bloqueados(const IPInfo ips[], int nips);
int  guardar_estado_ips(const char *ruta, const IPInfo ips[], int nips);
int  cargar_estado_ips(const char *ruta, IPInfo ips[], int *nips);
int  es_usuario_privilegiado(const char *username);

#endif /* SEGURIDAD_H */