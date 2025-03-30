#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <semaphore.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept
#define NUM_WORKERS 8

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
	pthread_mutex_t lock;
};

typedef struct {
    char **passwords;
    int start;
    int end;
    struct cracked_hash *cracked_hashes;
    int n_hashed;
    pthread_mutex_t *mutex;
} password_thread_arg_t;

static const char hex_chars[] = "0123456789abcdef";

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

int compare_hashes(char *a, char *b) {
	for(int i=0; i < 2*KEEP; i++)
		if(a[i] != b[i])
			return 0;
	return 1;
}



void *crack_thread_func(void *arg) {
    password_thread_arg_t *targ = (password_thread_arg_t *)arg;
    char hex_hash[2 * KEEP + 1];

    for (int p = targ->start; p < targ->end; p++) {
        char *password = targ->passwords[p];
		char cracked = 0;
        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));

            for (int j = 0; j < KEEP; j++)
                unsigned char byte = hash[j];
		hex_hash[2 * j]     = hex_chars[byte >> 4];
		hex_hash[2 * j + 1] = hex_chars[byte & 0x0F];
            hex_hash[2 * KEEP] = '\0';

            for (int j = 0; j < targ->n_hashed; j++) {
				if (compare_hashes(hex_hash, targ->cracked_hashes[j].hash)) {
					if (targ->cracked_hashes[j].password == NULL) {
						targ->cracked_hashes[j].password = strdup(password);
						targ->cracked_hashes[j].alg = algs[i];
					}

					break;
				}
            }
        }
    }

    return NULL;
}

// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	FILE *fp;
	char password[256];  // passwords have at most 255 characters
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

	pthread_t threads[NUM_WORKERS];//Declare 11 threads
	sem_t sem; //Declare semaphore
	sem_init(&sem, 0, 1); //Initialize semaphore
    int ids[3] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}; //Declare ids for threads

	// load hashed passwords
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hex_hash) == 1)
		n_hashed++;
	rewind(fp);
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
		pthread_mutex_init(&cracked_hashes[i].lock, NULL);
	}
	fclose(fp);

	// load common passwords, hash them, and compare them to hashed passwords
	fp = fopen(password_list, "r");
	assert(fp != NULL);
	char **passwords = NULL;

	int n_passwords = 0, cap = 1024;
	passwords = malloc(cap * sizeof(char*));
	assert(passwords);

	fp = fopen(password_list, "r");
	assert(fp);

	char buffer[256];
	while (fscanf(fp, "%s", buffer) == 1) {
		if (n_passwords == cap) {
			cap *= 2;
			passwords = realloc(passwords, cap * sizeof(char*));
		}
		passwords[n_passwords++] = strdup(buffer);
	}
	fclose(fp);

	password_thread_arg_t args[NUM_WORKERS];
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	int chunk = (n_passwords + NUM_WORKERS - 1) / NUM_WORKERS;

	for (int i = 0; i < NUM_WORKERS; i++) {
		args[i].passwords = passwords;
		args[i].start = i * chunk;
		args[i].end = (i + 1) * chunk > n_passwords ? n_passwords : (i + 1) * chunk;
		args[i].cracked_hashes = cracked_hashes;
		args[i].n_hashed = n_hashed;
		args[i].mutex = &mutex;

		pthread_create(&threads[i], NULL, crack_thread_func, &args[i]);
	}

	for (int i = 0; i < NUM_WORKERS; i++) {
		pthread_join(threads[i], NULL);
	}

	// print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}

