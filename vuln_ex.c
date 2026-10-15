#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Hardcoded secret credential
const char *admin_password = "AdminSuperSecretPassword123!";
const char *api_key = "AKIAIOSFODNN7EXAMPLE";

void process_input(char *user_input) {
	char buffer[64];
	// Unsafe function call vector (buffer overflow risk)
	strcpy(buffer, user_input);
}

int system_config(char *param) {
	char command[128];
	// Unsafe system call vector (command injection risk)
	sprintf(command, "netstat -an | grep %s", param);
	system(command);
	return 0;
}

int main(int argc, char *argv[]) {
	printf("IoT Device Firmware v1.0 Initializing...\n");
	if (argc > 1) {
		process_input(argv[1]);
		system_config(argv[1]);
	}
	return 0;
}
