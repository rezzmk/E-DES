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
#define MIN_SAMPLE_SIZE 1000

struct timespec diff(struct timespec start, struct timespec end) {
	struct timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
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

void sort(double results[], size_t size) {
    for (uint32_t i = 0; i < size - 1; i++) {
        for (uint32_t j = 0; j < size - i - 1; j++) {
            if (results[j] > results[j + 1]) {
                swap(&results[j], &results[j + 1]);
            }
        }
    }
}

double avg(double results[], size_t size) {
    double sum = 0;
    for (int i = 0; i < size; i++) {
        sum += results[i];
    }
    return sum / size;
}

double calculate_avg_time(double results[]) {
    sort(results, NUM_MEASUREMENTS);
    double *top1000 = get_first_n(MIN_SAMPLE_SIZE, results);
    return avg(top1000, MIN_SAMPLE_SIZE);
}

int main(int argc, char **args) {
    uint8_t *random_data = get_random_buf(BUF_SIZE);

    double des_results[NUM_MEASUREMENTS];
    clock_t time;

    for (int measurement = 0; measurement < NUM_MEASUREMENTS; measurement++) {
        uint8_t *key = get_random_buf(8);
        CAENC_CTX_new(DES, key);

	    struct timespec timer_start, timer_stop;
        clock_gettime(CLOCK_REALTIME, &timer_start);

        ENCRYPTION_RESULT *enc_result = encrypt(random_data, BUF_SIZE);
        ENCRYPTION_RESULT *dec_result = decrypt(enc_result->result, enc_result->length);

        clock_gettime(CLOCK_REALTIME, &timer_stop);
        double time_taken_in_seconds = (double)((timer_stop.tv_sec+timer_stop.tv_nsec*1e-9) - (double)(timer_start.tv_sec+timer_start.tv_nsec*1e-9));
        des_results[measurement] = time_taken_in_seconds;

        CAENC_CTX_cleanup();

        free(enc_result->result);
        free(enc_result);
        free(dec_result->result);
        free(dec_result);
    }

    double edes_results[NUM_MEASUREMENTS];
    for (int measurement = 0; measurement < NUM_MEASUREMENTS; measurement++) {
        uint8_t *key = get_random_buf(32);
        CAENC_CTX_new(EDES, key);

	    struct timespec timer_start, timer_stop;
        clock_gettime(CLOCK_REALTIME, &timer_start);

        ENCRYPTION_RESULT *enc_result = encrypt(random_data, BUF_SIZE);
        ENCRYPTION_RESULT *dec_result = decrypt(enc_result->result, enc_result->length);

        clock_gettime(CLOCK_REALTIME, &timer_stop);

        double time_taken_in_seconds = (double)((timer_stop.tv_sec+timer_stop.tv_nsec*1e-9) - (double)(timer_start.tv_sec+timer_start.tv_nsec*1e-9));
        edes_results[measurement] = time_taken_in_seconds;

        CAENC_CTX_cleanup();

        //time = clock() - time;
        //double time_taken_in_seconds = ((double) time) / CLOCKS_PER_SEC;

        for (int i = 0; i < dec_result->length; i++) {
            if (random_data[i] != dec_result->result[i]) {
                printf("Wrong byte\n");
            }
        }

        free(enc_result->result);
        free(enc_result);
        free(dec_result->result);
        free(dec_result);

    }

    printf("DES: %f ms\n", calculate_avg_time(des_results) * 1000);
    printf("E-DES: %f ms\n", calculate_avg_time(edes_results) * 1000);


    free(random_data);

    return 0;
}