#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 2048  // Larger to handle long requests

// Format string vulnerability
void handle_echo(char *request) {
    char *echo_start = strstr(request, "Echo: ");
    if (echo_start) {
        echo_start += strlen("Echo: ");
        char *end = strstr(echo_start, "\r\n");
        if (end) *end = '\0';

        printf(echo_start);  // VULNERABLE: direct printf on user input
        fflush(stdout);
    }
}

// Stack buffer overflow vulnerability
void parse_auth(char *request) {
    char buffer[64];  // Small stack buffer
    char *auth_start = strstr(request, "Auth: ");

    if (auth_start) {
        auth_start += strlen("Auth: ");
        char *end = strstr(auth_start, "\r\n");
        if (end) *end = '\0';

        strcpy(buffer, auth_start);  // VULNERABLE: no bounds check
        printf("Auth processed.\n");
    }
}

int main() {
    int server_fd, client_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char request_buffer[BUFFER_SIZE] = {0};

    const char *response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "Request OK\r\n";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Vulnerable HTTP server running on http://127.0.0.1:%d\n", PORT);
    printf("Use custom headers:\n");
    printf("  Echo: <format string>   → Format string vulnerability\n");
    printf("  Auth: <payload>         → Stack buffer overflow\n");

    while (1) {
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("accept");
            continue;
        }

        int bytes_read = read(client_socket, request_buffer, BUFFER_SIZE - 1);
        if (bytes_read > 0) {
            request_buffer[bytes_read] = '\0';
            printf("\n--- Received request ---\n%s--- End request ---\n", request_buffer);

            handle_echo(request_buffer);
            parse_auth(request_buffer);
        }

        write(client_socket, response, strlen(response));
        close(client_socket);
    }

    return 0;
}