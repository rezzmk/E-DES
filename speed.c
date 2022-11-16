#include "caencryption.h"
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <openssl/evp.h>
#include <string.h>
#include <assert.h>

#define NUM_MEASUREMENTS 100000
#define BUF_SIZE 4096
#define MIN_SAMPLE_SIZE 10000

/*
calculates the average of all values in a given array
*/ 
double avg(double input[], size_t size);
/*
calculates the benchmark result, given an array of multiple samples
*/ 
double get_benchmark_result(double results[]);
/*
sorts the input array
*/ 
void sort(double input[], size_t size);
/*
swaps two values
*/ 
void swap(double *xp, double *yp);

/*
gets the first n values from an array
*/ 
double *get_first_n(uint32_t first_n, double *original);
/*
generates a random buffer from /dev/urandom
*/ 
uint8_t *get_random_buf(size_t size);

int main(int argc, char **args) {
    printf("Running 100k iterations of encryption and decryption\n");
    printf("Generating random buffer of 4096B (from /dev/urandom)\n");

    printf("Each iteration will generate a new key of 32B (from /dev/urandom)\n");
    printf("Benchmark approach:\n");
    printf("\t1) Initialize new context with iteration key\n");
    printf("\t2) Start timer");
    printf("\t3) Encrypt and Decrypt pre-generated 4096B buffer\n");
    printf("\t4) Stop timer\n");
    printf("\t* This measures Wall-Time, not CPU time, external factors will impact the measurements\n");
    printf("\t* After the 100k iterations, an average of the best 10k is taken\n");
    printf("\t* Results will contain both Wall-Time and CPU-Time and both DES and E-DES will be tested\n");

    // Start out by getting a buffer with random data, which is fetched from /dev/urandom
    // BUF_SIZE = 4096B
    uint8_t *random_data = get_random_buf(BUF_SIZE);

    // DES Testing
    printf("\tTesting DES (Data Encryption Standard) in ECB mode now...\n");
    double des_results_wall_time[NUM_MEASUREMENTS];
    double des_results_cpu_time[NUM_MEASUREMENTS];
    for (int measurement = 0; measurement < NUM_MEASUREMENTS; measurement++) {
        if (measurement % 5000 == 0) {
            printf(". ");
            fflush(stdout);
        }

        uint8_t *key = get_random_buf(8);
        CAENC_CTX_new(DES, key);

        // For Wall-Time 
	    struct timespec timer_start, timer_stop;
        // For CPU Time 
        clock_t cpu_clock_time;

        // Start Wall-Time clock
        clock_gettime(CLOCK_REALTIME, &timer_start);
        // Start CPU-Time clock
        cpu_clock_time = clock();

        ENCRYPTION_RESULT *enc_result = encrypt(random_data, BUF_SIZE);
        ENCRYPTION_RESULT *dec_result = decrypt(enc_result->result, enc_result->length);

        // Stop timing
        clock_gettime(CLOCK_REALTIME, &timer_stop);
        cpu_clock_time = clock() - cpu_clock_time;

        // Calculates Wall-Time in seconds
        double wall_time_taken_in_seconds = (double)((timer_stop.tv_sec+timer_stop.tv_nsec * 1e-9) - (double)(timer_start.tv_sec+timer_start.tv_nsec * 1e-9));
        des_results_wall_time[measurement] = wall_time_taken_in_seconds;

        double cpu_time_taken_in_seconds = ((double) cpu_clock_time) / CLOCKS_PER_SEC;
        des_results_cpu_time[measurement] = cpu_time_taken_in_seconds;

        // Cleanup context for next iteration
        CAENC_CTX_cleanup();

        free(enc_result->result);
        free(enc_result);
        free(dec_result->result);
        free(dec_result);
    }

    // E-DES Testing
    printf("\n\tTesting E-DES (Enhanced Data Encryption Standard) in ECB mode now...\n");
    double edes_results_wall_time[NUM_MEASUREMENTS];
    double edes_results_cpu_time[NUM_MEASUREMENTS];
    for (int measurement = 0; measurement < NUM_MEASUREMENTS; measurement++) {
        if (measurement % 5000 == 0) {
            printf(". ");
            fflush(stdout);
        }

        uint8_t *key = get_random_buf(32);
        CAENC_CTX_new(EDES, key);

        // For Wall-Time 
	    struct timespec timer_start, timer_stop;
        // For CPU Time 
        clock_t cpu_clock_time;

        // Start Wall-Time clock
        clock_gettime(CLOCK_REALTIME, &timer_start);
        // Start CPU-Time clock
        cpu_clock_time = clock();

        ENCRYPTION_RESULT *enc_result = encrypt(random_data, BUF_SIZE);
        ENCRYPTION_RESULT *dec_result = decrypt(enc_result->result, enc_result->length);

        // Stop timing
        clock_gettime(CLOCK_REALTIME, &timer_stop);
        cpu_clock_time = clock() - cpu_clock_time;

        // Calculates Wall-Time in seconds
        double wall_time_taken_in_seconds = (double)((timer_stop.tv_sec+timer_stop.tv_nsec * 1e-9) - (double)(timer_start.tv_sec+timer_start.tv_nsec * 1e-9));
        edes_results_wall_time[measurement] = wall_time_taken_in_seconds;

        double cpu_time_taken_in_seconds = ((double) cpu_clock_time) / CLOCKS_PER_SEC;
        edes_results_cpu_time[measurement] = cpu_time_taken_in_seconds;

        // Cleanup context for next iteration
        CAENC_CTX_cleanup();

        free(enc_result->result);
        free(enc_result);
        free(dec_result->result);
        free(dec_result);

    }

    // Print results
    printf("\n\nPreparing results...\n");
    printf(
        "\tDES Results: Wall-Time averages %f ms, CPU-Time averages %f ms\n", 
        get_benchmark_result(des_results_wall_time) * 1000,
        get_benchmark_result(des_results_cpu_time) * 1000
    );

    printf(
        "\tE-DES Results: Wall-Time averages %f ms, CPU-Time averages %f ms\n", 
        get_benchmark_result(edes_results_wall_time) * 1000,
        get_benchmark_result(edes_results_cpu_time) * 1000
    );

    free(random_data);

    return 0;
}

uint8_t *get_random_buf(size_t size) {
    uint32_t random_data = open("/dev/urandom", O_RDONLY);
    if (random_data < 0) {

    }
    else {
        uint8_t *result = calloc(size, sizeof(uint8_t));
        size_t bytes_read = read(random_data, result, size * sizeof(uint8_t));
        if (bytes_read < 0) {

        }

        return result;
    }
}

double *get_first_n(uint32_t first_n, double *original) {
    double *results = calloc(first_n, sizeof(double));
    for (int i = 0; i < first_n; i++) {
        results[i] = original[i];
    }
    return results;
}

void swap(double* xp, double* yp) {
    double temp = *xp;
    *xp = *yp;
    *yp = temp;
}

void sort(double input[], size_t size) {
    for (uint32_t i = 0; i < size - 1; i++) {
        for (uint32_t j = 0; j < size - i - 1; j++) {
            if (input[j] > input[j + 1]) {
                swap(&input[j], &input[j + 1]);
            }
        }
    }
}

double avg(double input[], size_t size) {
    double sum = 0;
    for (int i = 0; i < size; i++) {
        sum += input[i];
    }
    return sum / size;
}

double get_benchmark_result(double results[]) {
    sort(results, NUM_MEASUREMENTS);
    double *top1000 = get_first_n(MIN_SAMPLE_SIZE, results);
    return avg(top1000, MIN_SAMPLE_SIZE);
}