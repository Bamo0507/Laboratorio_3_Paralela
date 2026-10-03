/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Miembros:    Adriana Palacios
 *              Bryan Martinez
 *              Daniela Ramirez
 * Ejercicio:   Busqueda paralela de una clave AES mediante fuerza bruta
 * Descripcion: los procesos MPI se reparten las claves candidatas y
 *              se detienen juntos al encontrar la clave o agotar el rango.
 *
 *              Uso: mpirun -np n ./busqueda_clave_aes_mpi
 *                       [bits] [clave_secreta] [mensaje]
 *----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <mpi.h>
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

/* Candidatas que prueba cada proceso antes de sincronizarse. */
#define CHECK_INTERVAL 4096

/* Muestra el error y aborta todos los procesos. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
}

/* Convierte un argumento a entero sin signo; devuelve 0 si no es valido. */
static int parse_u64(const char *text, uint64_t *value)
{
    char *end;

    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);

    if (errno != 0 || *end != '\0' || text[0] == '-' || text[0] == '\0') {
        return 0;
    }

    *value = (uint64_t)parsed;
    return 1;
}

/*
 * La clave usa los 16 bytes de una base aleatoria. Solo los ultimos
 * `bits` bits se reemplazan por la candidata.
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

/* AES-128-CTR: cifrar y descifrar son la misma operacion. */
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

int main(int argc, char *argv[])
{
    int rank;
    int size;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    /* Todos los procesos leen los mismos argumentos, por lo que
     * todos llegan a la misma conclusion sobre si son validos. */
    uint64_t bits_arg = DEFAULT_BITS;
    uint64_t secret = 0;
    const char *message = (argc > 3) ? argv[3] : DEFAULT_MESSAGE;
    int valid = 1;

    if (argc > 4) {
        valid = 0;
        if (rank == 0) {
            fprintf(stderr, "Uso: mpirun -np n %s [bits] [clave_secreta] [mensaje]\n",
                    argv[0]);
        }
    } else if (argc > 1 && !parse_u64(argv[1], &bits_arg)) {
        valid = 0;
        if (rank == 0) {
            fprintf(stderr, "Valor invalido para bits: %s\n", argv[1]);
        }
    } else if (bits_arg < MIN_BITS || bits_arg > MAX_BITS) {
        valid = 0;
        if (rank == 0) {
            fprintf(stderr, "bits debe estar entre %d y %d.\n", MIN_BITS, MAX_BITS);
        }
    } else if (argc > 2 && !parse_u64(argv[2], &secret)) {
        valid = 0;
        if (rank == 0) {
            fprintf(stderr, "Valor invalido para clave_secreta: %s\n", argv[2]);
        }
    } else if (strlen(message) == 0 || strlen(message) > MAX_MESSAGE_LEN) {
        valid = 0;
        if (rank == 0) {
            fprintf(stderr, "El mensaje debe tener entre 1 y %d bytes.\n",
                    MAX_MESSAGE_LEN);
        }
    }

    if (!valid) {
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    int bits = (int)bits_arg;
    uint64_t total_keys = UINT64_C(1) << bits;

    /* Por defecto se usa el peor caso: la ultima candidata. */
    if (argc <= 2) {
        secret = total_keys - 1;
    } else if (secret >= total_keys) {
        if (rank == 0) {
            fprintf(stderr, "clave_secreta debe ser menor que 2^%d.\n", bits);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    int message_len = (int)strlen(message);
    int prefix_len = (message_len < PREFIX_LEN) ? message_len : PREFIX_LEN;

    /* Cifrador obtenido una sola vez por proceso. */
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

    /* Solo el rank 0 prepara el mensaje cifrado,
     * porque cada proceso generaria valores aleatorios distintos. */
    if (rank == 0) {
        if (RAND_bytes(base_key, KEY_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) {
            fail("No se pudieron generar datos aleatorios.");
        }

        make_key(base_key, secret, bits, key);
        crypt_ctr(ctx, cipher, key, iv,
                  (const unsigned char *)message, cipher_text, message_len);
    }

    /* Todos reciben la parte conocida de la clave, el IV y el texto cifrado. */
    MPI_Bcast(base_key, KEY_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(iv, IV_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(cipher_text, message_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    uint64_t local_found = UINT64_MAX;
    uint64_t global_found = UINT64_MAX;
    uint64_t local_tested = 0;
    uint64_t total_tested = 0;
    uint64_t round_size = (uint64_t)CHECK_INTERVAL * (uint64_t)size;

    /* Todos inician la medicion al mismo tiempo. */
    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    /*
     * Cada ronda cubre round_size candidatas consecutivas. Como el inicio
     * de cada ronda es multiplo de size, el proceso r prueba exactamente
     * las candidatas c con c % size == r. Todos ejecutan el mismo numero
     * de rondas, por lo que todos llegan a cada MPI_Allreduce.
     */
    for (uint64_t round = 0; round < total_keys; round += round_size) {
        uint64_t round_end = round + round_size;

        if (round_end > total_keys) {
            round_end = total_keys;
        }

        for (uint64_t candidate = round + (uint64_t)rank;
             candidate < round_end;
             candidate += (uint64_t)size) {
            make_key(base_key, candidate, bits, key);

            /* Solo se descifra el prefijo conocido. */
            crypt_ctr(ctx, cipher, key, iv, cipher_text, plain, prefix_len);
            local_tested++;

            if (memcmp(plain, message, prefix_len) == 0) {
                local_found = candidate;
                break;
            }
        }

        /* Si algun proceso encontro la clave, todos la conocen y se detienen. */
        MPI_Allreduce(&local_found, &global_found, 1,
                      MPI_UINT64_T, MPI_MIN, MPI_COMM_WORLD);

        if (global_found != UINT64_MAX) {
            break;
        }
    }

    double local_elapsed = MPI_Wtime() - start;
    double elapsed = 0.0;

    /* El tiempo de la ejecucion es el del proceso que tardo mas. */
    MPI_Reduce(&local_elapsed, &elapsed, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    MPI_Reduce(&local_tested, &total_tested, 1,
               MPI_UINT64_T, MPI_SUM, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        printf("Ejecucion: paralela con %d procesos\n", size);
        printf("Rango explorado: 2^%d candidatas\n", bits);

        if (global_found != UINT64_MAX) {
            make_key(base_key, global_found, bits, key);
            crypt_ctr(ctx, cipher, key, iv, cipher_text, plain, message_len);

            printf("Clave encontrada: candidata %" PRIu64
                   " (proceso %" PRIu64 ")\n",
                   global_found, global_found % (uint64_t)size);
            printf("Clave AES-128: ");
            print_hex(key, KEY_LEN);
            printf("Mensaje: ");
            fwrite(plain, 1, (size_t)message_len, stdout);
            putchar('\n');
        } else {
            printf("No se encontro la clave.\n");
        }

        printf("Candidatas probadas: %" PRIu64 "\n", total_tested);
        printf("Tiempo: %.6f segundos\n", elapsed);

        if (elapsed > 0.0) {
            printf("Rendimiento: %.0f candidatas/segundo\n",
                   (double)total_tested / elapsed);
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    MPI_Finalize();

    return EXIT_SUCCESS;
}
