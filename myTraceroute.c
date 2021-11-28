#include "myTraceroute.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#define ERROR -1				// Признак ошибки
#define EQUAL  0				// Признак равенства

#define IP_HDR_SIZE   20		// Минимальная длина IP-пакета
#define ICMP_HDR_SIZE 8			// Минимальная длина ICMP-пакета
#define PACKAGE_SIZE  29		// Размер пакета для отправки

#define ICMP_MSG_SIZE 4			// Размер ICMP сообщения

#define TTL_COUNT 	   30		// Количество прыжков
#define PACKAGES_COUNT 3		// Количество пакетов за отправку

#define ECHO_ANSWER_TYPE 0		// Тип эхо-ответа

#define PACKAGE_WAITTIME 800000	// Время ожидания ответного пакета

#define IP_LEN 16				// Длина IP-адреса
#define HDR_CHECKSUM_LEN 16		// Длина контрольной суммы заголовка


// Получить IP-адрес по имени хоста
static bool getIPFromHostname(const char* hostname, char* host_ip) {
	struct hostent* he;
	struct in_addr** addr_list;

	if ((he = gethostbyname(hostname)) == NULL) {
		herror("gethostbyname");
		return false;
	}

	addr_list = (struct in_addr**)he->h_addr_list;

	for (int i = 0; addr_list[i] != NULL; ++i) {
		strcpy(host_ip, inet_ntoa(*addr_list[i]));
		return true;
	}

	return false;
}

// Получить контрольную сумму заголовка
static unsigned short getCheckSum(unsigned short* buf, int nwords) {
	unsigned short sum = 0;

	for (; 0 < nwords; --nwords)
		sum += *buf++;

	sum = (sum >> HDR_CHECKSUM_LEN) + (sum & 0xffff);
	sum += (sum >> HDR_CHECKSUM_LEN);

	return ~sum;
}

// Получить сокет
static int getSocket(int domain, int type, int protocol) {
	int ret_value;

	if ((ret_value = socket(domain, type, protocol)) == ERROR) {
		perror("socket() error");
		exit(EXIT_FAILURE);
	}

	return ret_value;
}

// Инициализировать заголовок IP-пакета
static void initIPHeader(char package[PACKAGE_SIZE], uint8_t ttl, const char* host_ip) {
	struct ip* ip_hdr = (struct ip*)package;

	ip_hdr->ip_hl = 5;					// Длина заголовка IP-пакета
	ip_hdr->ip_v = 4;					// Версия протокола
	ip_hdr->ip_tos = 0;					// Сервис
	ip_hdr->ip_len = PACKAGE_SIZE;		// Размер пакета
	ip_hdr->ip_id = getpid();			// Идентификатор пакета
	ip_hdr->ip_off = 0;					// Отступ 
	ip_hdr->ip_ttl = ttl;				// Число маршрутов, которое может пройти пакет
	ip_hdr->ip_p = IPPROTO_ICMP;		// Сетевой протокол 

	inet_pton(AF_INET, host_ip, &ip_hdr->ip_dst);
	ip_hdr->ip_sum = getCheckSum((unsigned short*)package, ICMP_HDR_SIZE);
}

// Инициализировать заголовок ICMP-пакета
static void initICMPHeader(char package[PACKAGE_SIZE], uint8_t ttl) {
	struct icmphdr* icmp_hdr = (struct icmphdr*)(package + IP_HDR_SIZE);

	icmp_hdr->type = ICMP_ECHO;			// Тип заголовка: эхо-ответ
	icmp_hdr->code = 0;					// Код
	icmp_hdr->checksum = 0;					// Контрольная сумма
	icmp_hdr->un.echo.id = getpid();		// 		
	icmp_hdr->un.echo.sequence = ttl + 1;
	icmp_hdr->checksum = getCheckSum((unsigned short*)(package + IP_HDR_SIZE), ICMP_MSG_SIZE);
}

// Получить инициализированный удалённый адрес
static struct sockaddr_in getInitedRemoteAddress(const char* host_ip) {
	struct sockaddr_in remote_addr;
	remote_addr.sin_family = AF_INET;
	inet_pton(AF_INET, host_ip, &remote_addr.sin_addr);

	return remote_addr;
}

// Отправить пакет
static void sendPacket(int sock, const char* host_ip, uint8_t ttl) {
	char package[PACKAGE_SIZE] = { 0 };

	initIPHeader(package, ttl, host_ip);	// Инициализировать IP-заголовок
	initICMPHeader(package, ttl);			// Инициализировать ICMP-заголовок

	// Получить удалённый адрес
	struct sockaddr_in remote_addr = getInitedRemoteAddress(host_ip);

	// Устанавливаем фраги отправки IP пакета на сокете
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &ttl, sizeof ttl);
	sendto(sock, package, PACKAGE_SIZE, 0, (struct sockaddr*) & remote_addr, sizeof(struct sockaddr_in));
}

// Принять пакет и вернуть IP-адрес
static const char* recvPacket(int sock, char package[PACKAGE_SIZE]) {
	struct sockaddr_in reached_addr;
	socklen_t len = sizeof(struct sockaddr_in);

	// Устанавливаем максимальное время ожидания пакета
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = PACKAGE_WAITTIME;

	// Устанавливаем флаги для установки времени ожидания пакета
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
	ssize_t recv_val = recvfrom(sock, package, PACKAGE_SIZE, 0, (struct sockaddr*) & reached_addr, &len);

	return recv_val == ERROR ? "EMPTY" : inet_ntoa(reached_addr.sin_addr);
}

// Получаем тип ICMP-пакета
static uint8_t getICMPPacketType(char package[PACKAGE_SIZE]) {
	struct icmphdr* reached_icmp_hdr = (struct icmphdr*)(package + IP_HDR_SIZE);

	return reached_icmp_hdr->type;
}

// Получить прошедшее время от начала работы
static double getTimeout(struct timeval start) {
	struct timeval end;
	gettimeofday(&end, NULL);

	double seconds = end.tv_sec - start.tv_sec;
	double useconds = end.tv_usec - start.tv_usec;

	return (seconds * 1000.0 + useconds / 1000.0) + 0.5;
}

// Определить маршрут следования в сети
void myTraceroute(const char* hostname) {
	char host_ip[IP_LEN];

	// Получить имя хоста по IP-адресу
	getIPFromHostname(hostname, host_ip);

	if (strcmp(host_ip, "EMPTY") != EQUAL) {
		printf("traceroute to %s (%s), 30 hops max:\n", hostname, host_ip);

		int sock = getSocket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

		bool reached = false;
		for (uint8_t ttl = 1; ttl <= TTL_COUNT && !reached; ++ttl) {

			struct timeval start;
			gettimeofday(&start, NULL);

			for (uint8_t packet_num = 0; packet_num != PACKAGES_COUNT; ++packet_num)
				sendPacket(sock, host_ip, ttl);

			printf("%hhu \t", ttl);

			uint8_t packet_success_count = 0;
			for (uint8_t packet_num = 0; packet_num != PACKAGES_COUNT; ++packet_num) {
				char recv_package[PACKAGE_SIZE] = { 0 };

				const char* recv_ip = recvPacket(sock, recv_package);

				if (strcmp(recv_ip, "EMPTY") == EQUAL)
					printf("* ");
				else {
					switch (packet_num) {
					case 0: printf("%s\t %06.3lf ms  ", recv_ip, getTimeout(start)); break;
					case 1:
					case 2: printf("%06.3lf ms  ", getTimeout(start)); break;
					}

					if (getICMPPacketType(recv_package) == ECHO_ANSWER_TYPE)
						++packet_success_count;
				}

				if (0 < packet_success_count)
					reached = true;
			}

			printf("\n");
		}
	}
	else
		fprintf(stderr, "Error: wrong hostname!\n");
}
