/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Miembros:    Adriana Palacios
 *              Bryan Martinez
 *              Daniela Ramirez
 * Ejercicio:   Busqueda secuencial de una clave AES mediante fuerza bruta
 * Descripcion: un unico proceso prueba claves candidatas en orden
 *              y verifica cada una con el prefijo conocido del mensaje.
 *
 *              Uso: ./busqueda_clave_aes_secuencial_mejorado
 *                       [bits] [clave_secreta] [mensaje]
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define KEY_LEN 16
#define IV_LEN 16
#define MAX_MESSAGE_LEN 256
#define PREFIX_LEN 8
#define MIN_BITS 1
#define MAX_BITS 40
#define DEFAULT_BITS 24
#define DEFAULT_MESSAGE "Puedes lograrlo!"

/* Muestra el error y termina el programa. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/* Convierte un argumento a entero sin signo; termina si no es valido. */
static uint64_t parse_u64(const char *text, const char *name)
{
    char *end;

    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);

    if (errno != 0 || *end != '\0' || text[0] == '-' || text[0] == '\0') {
        fprintf(stderr, "Valor invalido para %s: %s\n", name, text);
        exit(EXIT_FAILURE);
    }

    return (uint64_t)value;
}

/*
 * La clave usa los 16 bytes de una base aleatoria. Solo los ultimos
 * `bits` bits se reemplazan por la candidata: se simula que el atacante
 * conoce el resto de la clave y debe adivinar unicamente esa parte.
 */
static void make_key(
    const unsigned char base[KEY_LEN],
    uint64_t candidate,
    int bits,
    unsigned char key[KEY_LEN])
{
    uint64_t mask = (UINT64_C(1) << bits) - 1;
    uint64_t tail = 0;

    memcpy(key, base, KEY_LEN);

    /* Los ultimos 8 bytes como entero big-endian. */
    for (int i = 0; i < 8; i++) {
        tail = (tail << 8) | key[8 + i];
    }

    tail = (tail & ~mask) | (candidate & mask);

    for (int i = 7; i >= 0; i--) {
        key[8 + i] = (unsigned char)(tail & 0xFF);
        tail >>= 8;
    }
}

/*
 * AES-128-CTR: cifrar y descifrar son la misma operacion, por lo
 * que no hace falta indicar la direccion. El IV es publico: quien
 * descifra tambien lo conoce. CTR no requiere relleno.
 */
static void crypt_ctr(
    EVP_CIPHER_CTX *ctx,
    const EVP_CIPHER *cipher,
    const unsigned char key[KEY_LEN],
    const unsigned char iv[IV_LEN],
    const unsigned char *input,
    unsigned char *output,
    int len)
{
    int written = 0;
    int final_written = 0;

    if (EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1) != 1) {
        fail("Error al inicializar AES.");
    }

    if (EVP_CipherUpdate(ctx, output, &written, input, len) != 1) {
        fail("Error al procesar el mensaje.");
    }

    if (EVP_CipherFinal_ex(ctx, output + written, &final_written) != 1) {
        fail("Error al finalizar la operacion AES.");
    }

    if (written + final_written != len) {
        fail("Longitud inesperada del resultado.");
    }
}

static void print_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

/* Obtiene el tiempo de un reloj monotono, en segundos. */
static double get_time(void)
{
    struct timespec current;

    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        perror("Error al consultar el reloj");
        exit(EXIT_FAILURE);
    }

    return (double)current.tv_sec +
           (double)current.tv_nsec / 1000000000.0;
}

int main(int argc, char *argv[])
{
    if (argc > 4) {
        fprintf(stderr, "Uso: %s [bits] [clave_secreta] [mensaje]\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint64_t bits_arg = (argc > 1) ? parse_u64(argv[1], "bits") : DEFAULT_BITS;

    if (bits_arg < MIN_BITS || bits_arg > MAX_BITS) {
        fprintf(stderr, "bits debe estar entre %d y %d.\n", MIN_BITS, MAX_BITS);
        return EXIT_FAILURE;
    }

    int bits = (int)bits_arg;
    uint64_t total_keys = UINT64_C(1) << bits;

    /* Por defecto se usa el peor caso: la ultima candidata. */
    uint64_t secret = (argc > 2) ? parse_u64(argv[2], "clave_secreta")
                                 : total_keys - 1;

    if (secret >= total_keys) {
        fprintf(stderr, "clave_secreta debe ser menor que 2^%d.\n", bits);
        return EXIT_FAILURE;
    }

    const char *message = (argc > 3) ? argv[3] : DEFAULT_MESSAGE;
    size_t message_size = strlen(message);

    if (message_size == 0 || message_size > MAX_MESSAGE_LEN) {
        fprintf(stderr, "El mensaje debe tener entre 1 y %d bytes.\n",
                MAX_MESSAGE_LEN);
        return EXIT_FAILURE;
    }

    int message_len = (int)message_size;
    int prefix_len = (message_len < PREFIX_LEN) ? message_len : PREFIX_LEN;

    /* Cifrador obtenido una sola vez. */
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-128-CTR", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (cipher == NULL || ctx == NULL) {
        fail("No se pudo preparar OpenSSL.");
    }

    unsigned char base_key[KEY_LEN];
    unsigned char iv[IV_LEN];
    unsigned char key[KEY_LEN];
    unsigned char cipher_text[MAX_MESSAGE_LEN];
    unsigned char plain[MAX_MESSAGE_LEN];

    /* Clave base e IV aleatorios con el generador seguro de OpenSSL. */
    if (RAND_bytes(base_key, KEY_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
        fail("No se pudieron generar datos aleatorios.");
    }

    /* Preparacion del ejercicio: se cifra el mensaje con la clave secreta. */
    make_key(base_key, secret, bits, key);
    crypt_ctr(ctx, cipher, key, iv,
              (const unsigned char *)message, cipher_text, message_len);

    uint64_t found = UINT64_MAX;
    uint64_t tested = 0;

    /* La medicion comienza despues de preparar el mensaje. */
    double start = get_time();

    for (uint64_t candidate = 0; candidate < total_keys; candidate++) {
        make_key(base_key, candidate, bits, key);

        /* Solo se descifra el prefijo conocido: en CTR no es
         * necesario procesar el resto del mensaje para verificar. */
        crypt_ctr(ctx, cipher, key, iv, cipher_text, plain, prefix_len);
        tested++;

        if (memcmp(plain, message, prefix_len) == 0) {
            found = candidate;
            break;
        }
    }

    double elapsed = get_time() - start;

    printf("Ejecucion: secuencial\n");
    printf("Rango explorado: 2^%d candidatas\n", bits);

    if (found != UINT64_MAX) {
        /* Con la clave encontrada se descifra el mensaje completo. */
        make_key(base_key, found, bits, key);
        crypt_ctr(ctx, cipher, key, iv, cipher_text, plain, message_len);

        printf("Clave encontrada: candidata %" PRIu64 "\n", found);
        printf("Clave AES-128: ");
        print_hex(key, KEY_LEN);
        printf("Mensaje: ");
        fwrite(plain, 1, (size_t)message_len, stdout);
        putchar('\n');
    } else {
        printf("No se encontro la clave.\n");
    }

    printf("Candidatas probadas: %" PRIu64 "\n", tested);
    printf("Tiempo: %.6f segundos\n", elapsed);

    if (elapsed > 0.0) {
        printf("Rendimiento: %.0f candidatas/segundo\n", (double)tested / elapsed);
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    return EXIT_SUCCESS;
}
