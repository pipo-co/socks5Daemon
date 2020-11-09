#ifndef CLIENT_COMMAND_CONTROLLER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6
#define CLIENT_COMMAND_CONTROLLER_H_00180a6350a1fbe79f133adf0a96eb6685c242b6

#define COMMAND_COUNT 18

typedef struct CommandController {
	void (*sender)(int);
	void (*receiver)(int);	
} CommandController;

void client_command_controller_init(CommandController controllers[]);

#endif