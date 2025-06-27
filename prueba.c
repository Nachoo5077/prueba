#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "seguridad.h"

int main(void) {
    printf("Iniciando programa...\n");
    fflush(stdout);
    LogEntry logs[MAX_ENTRIES];
    IPInfo ips[MAX_UNIQUE_IPS];
    int nlogs = 0, nips = 0;
    int choice;
    char filename[MAX_LEN];

    printf("Programa inicializado correctamente.\n");
    fflush(stdout);

    // Cargar estado previo de IPs bloqueadas
    printf("Cargando estado previo...\n");
    cargar_estado_ips("estado_ips.dat", ips, &nips);
    if (nips > 0) {
        printf("Se encontraron %d IPs con historial previo.\n", nips);
    }

    do {
        printf("\n=== Menú Protección de Login ===\n");
        printf("1. Cargar uno o más archivos de log\n");
        printf("2. Analizar IPs maliciosas\n");
        printf("3. Guardar intentos fallidos\n");
        printf("4. Mostrar IPs bloqueadas\n");
        printf("5. Salir\n");
        printf("Seleccione opción: ");
        fflush(stdout);
        char input[10];
        if (!fgets(input, sizeof(input), stdin)) break;
        choice = atoi(input);
        switch (choice) {
            case 1: {
                int files;
                printf("¿Cuántos archivos de log desea cargar?: ");
                char fileInput[10];
                if (!fgets(fileInput, sizeof(fileInput), stdin)) {
                    printf("Entrada inválida.\n");
                    break;
                }
                files = atoi(fileInput);
                if (files < 1) {
                    printf("Entrada inválida.\n");
                    break;
                }
                for (int f = 0; f < files; f++) {
                    printf("Ruta al log %d: ", f+1);
                    fgets(filename, sizeof(filename), stdin);
                    filename[strcspn(filename, "\n")] = '\0';
                    int loaded = cargar_log(filename, logs + nlogs);
                    if (loaded < 0) {
                        printf("Error al abrir %s\n", filename);
                    } else {
                        printf("Cargados %d registros de %s.\n", loaded, filename);
                        nlogs += loaded;
                    }
                }
                break;
            }
            case 2:
                if (nlogs > 0) {
                    analizar_intentos(logs, nlogs, ips, &nips);
                    printf("Analizado: %d IPs procesadas.\n", nips);
                } else {
                    printf("Primero cargue archivos de log.\n");
                }
                break;
            case 3:
                if (nlogs > 0 && nips > 0) {
                    guardar_fallidos("Intentos_de_login_fallidos.log",
                                     logs, nlogs, ips, nips);
                    printf("Guardado en Intentos_de_login_fallidos.log\n");
                } else {
                    printf("No hay datos para guardar.\n");
                }
                break;
            case 4:
                if (nips > 0) {
                    mostrar_bloqueados(ips, nips);
                } else {
                    printf("No hay IPs bloqueadas.\n");
                }
                break;
            case 5:
                printf("Guardando estado...\n");
                if (nips > 0) {
                    guardar_estado_ips("estado_ips.dat", ips, nips);
                }
                printf("Adiós.\n");
                break;
            default:
                printf("Opción inválida.\n");
        }
    } while (choice != 5);

    return 0;
}