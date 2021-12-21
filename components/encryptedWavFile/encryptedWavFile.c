#include <aes/esp_aes.h>
#include <esp_log.h>
#include <stdio.h>
#include <string.h>

#include "encryptedWavFile.h"
#include "encrypter.h"

static const char* TAG = "encryptedWavFile";

void encryptedWavFile_init(encryptedWavFile_t* self, FILE* fd, int sample_rate,
                           size_t buffer_length)
{
    encrypter_init(&self->encrypter, sizeof(int16_t), buffer_length);

    strcpy(self->header.riff_header, "RIFF");
    self->header.wav_size = 0;
    strcpy(self->header.wave_header, "WAVE");
    strcpy(self->header.fmt_header, "fmt ");
    self->header.fmt_chunk_size = 16;
    self->header.audio_format = 1;
    self->header.num_channels = 1;
    self->header.sample_rate = sample_rate;
    self->header.byte_rate = 32000;
    self->header.sample_alignment = 2;
    self->header.bit_depth = 16;
    strcpy(self->header.data_header, "data");
    self->header.data_bytes = 0;
    self->header.data_bytes = 204848 - sizeof(encrypted_wav_header_t);
    self->header.wav_size = 204848 - 8;

    self->fd = fd;
    self->buffer_length = buffer_length;

    self->header.data_bytes = self->file_size - sizeof(encrypted_wav_header_t);
    self->header.wav_size = self->file_size - 8;
    ESP_LOGI(TAG, "header size = %u", sizeof(encrypted_wav_header_t));

    size_t encrypted_header_size = sizeof(encrypted_wav_header_t);
    size_t encrypted_header_length = 1;
    encrypted_wav_header_t* encrypted_header = encrypter_crypt_specific(
        &self->encrypter, &self->header, &encrypted_header_size,
        &encrypted_header_length);
    fwrite(encrypted_header, encrypted_header_size, encrypted_header_length,
           self->fd);
    free(encrypted_header);

    self->file_size = encrypted_header_length * encrypted_header_size;
}

void encryptedWavFile_write(encryptedWavFile_t* self, int16_t** samples)
{
    encrypter_crypt(&self->encrypter, (void**)samples);
    // write the samples and keep track of the file size so far
    fwrite(*samples, sizeof(int16_t), self->buffer_length, self->fd);
    self->file_size += sizeof(int16_t) * self->buffer_length;
}

void encryptedWavFile_finish(encryptedWavFile_t* self)
{
    ESP_LOGI(TAG, "WAV file size: %d", self->file_size);

    encrypter_finish(&self->encrypter);
}
