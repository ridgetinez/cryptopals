#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 80  // the port users will be connecting to
#define WEBROOT "./webroot"  // The webserver's root directory

void fatal(char *err_msg);
void handle_connection(int sock, struct sockaddr_in *client);

int 
main(void)
{
    int sockfd, new_sockfd, yes=1;
    struct sockaddr_in host_addr, client_addr;
    socklen_t sin_size;

    printf("Accepting web requests on port %d\n", PORT);

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) 
        fatal("in socket");

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) 
        fatal("setting socket option SO_REUSEADDR");

    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(PORT);
    host_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(host_addr.sin_zero), '\0', 8);

    if (bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)
        fatal("binding to socket");
    
    if (listen(sockfd, 20) == -1)
        fatal("listening on socket");

    while (1) {
        sin_size = sizeof(struct sockaddr_in);
        new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
        if (new_sockfd == -1)
            fatal("accepting connection");
        
        handle_connection(new_sockfd, &client_addr);
    }

    return 0;
}

void 
fatal(char *err_msg)
{
    fprintf(stderr, "error: %s\n", err_msg);
    exit(1);
}