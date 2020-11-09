#include "client/clientCommandController.h"
#include "client/clientSenders.h"
#include "client/clientReceivers.h"
#include "client/clientDefs.h"

#include <stdint.h>
#include <stdlib.h>

typedef enum CommandControllerStartIndex {
    CCSI_QUERIES        = 0,
    CCSI_MODIFICATIONS  = CTCC_QUERY_COUNT,
} CommandControllerStartIndex;

static void client_command_controller_load_queries(CommandController controllers[], char *descriptions[]);
static void client_command_controller_load_modifications(CommandController controllers[], char *descriptions[]);

void client_command_controller_init(CommandController controllers[], char *descriptions[]) {
    
    client_command_controller_load_queries(controllers, descriptions);

    client_command_controller_load_modifications(controllers, descriptions);
}

static void client_command_controller_load_queries(CommandController controllers[], char *descriptions[]) {
    
    size_t index = CCSI_QUERIES;

    // X'00'   List Users
    controllers[index + CQ_LIST_USERS].sender = list_users_sender;
    controllers[index + CQ_LIST_USERS].receiver = list_users_receiver;
    descriptions[index + CQ_LIST_USERS] = "List Users";
    
    // X'01'   Get Total Historic Connections
    controllers[index + CQ_TOTAL_HISTORIC_CONNECTIONS].sender = total_historic_connections_sender;
    controllers[index + CQ_TOTAL_HISTORIC_CONNECTIONS].receiver = total_historic_connections_receiver;
    descriptions[index + CQ_TOTAL_HISTORIC_CONNECTIONS] = "Get Total Historic Connections";

    // X'02'   Get Current Connections
    controllers[index + CQ_CURRENT_CONNECTIONS].sender = current_connections_sender;
    controllers[index + CQ_CURRENT_CONNECTIONS].receiver = current_connections_receiver;
    descriptions[index + CQ_CURRENT_CONNECTIONS] = "Get Current Connections";

    // X'03'   Get Max. Concurrent Connections
    controllers[index + CQ_MAX_CURRENT_CONECTIONS].sender = max_concurrent_conections_sender;
    controllers[index + CQ_MAX_CURRENT_CONECTIONS].receiver = max_concurrent_conections_receiver;
    descriptions[index + CQ_MAX_CURRENT_CONECTIONS] = "Get Max. Concurrent Connections";
    
    // X'04'   Get Total Sent Bytes
    controllers[index + CQ_TOTAL_BYTES_SENT].sender = total_bytes_sent_sender;
    controllers[index + CQ_TOTAL_BYTES_SENT].receiver = total_bytes_sent_receiver;
    descriptions[index + CQ_TOTAL_BYTES_SENT] = "Get Total Sent Bytes";
    
    // X'05'   Get Total Received Bytes
    controllers[index + CQ_TOTAL_BYTES_RECEIVED].sender = total_bytes_received_sender;
    controllers[index + CQ_TOTAL_BYTES_RECEIVED].receiver = total_bytes_received_receiver;
    descriptions[index + CQ_TOTAL_BYTES_RECEIVED] = "Get Total Received Bytes";
    
    // X'06'   Get Number of Users Connected
    controllers[index + CQ_CONNECTED_USERS].sender = connected_users_sender;
    controllers[index + CQ_CONNECTED_USERS].receiver = connected_users_receiver;
    descriptions[index + CQ_CONNECTED_USERS] = "Get Number of Users Connected";

    // X'07'   Get Total User Count
    controllers[index + CQ_USER_COUNT].sender = user_count_sender;
    controllers[index + CQ_USER_COUNT].receiver = user_count_receiver;
    descriptions[index + CQ_USER_COUNT] = "Get Total User Count";

    // X'08'   Get I/O Buffer Sizes
    controllers[index + CQ_BUFFER_SIZES].sender = buffer_sizes_sender;
    controllers[index + CQ_BUFFER_SIZES].receiver = buffer_sizes_receiver;
    descriptions[index + CQ_BUFFER_SIZES] = "Get I/O Buffer Sizes";

    // X'09'   Get Selector Timeout
    controllers[index + CQ_SELECTOR_TIMEOUT].sender = selector_timeout_sender;
    controllers[index + CQ_SELECTOR_TIMEOUT].receiver = selector_timeout_receiver;
    descriptions[index + CQ_SELECTOR_TIMEOUT] = "Get Selector Timeout";

    // X'0A'   Get Connection Timeout
    controllers[index + CQ_CONNECTION_TIMEOUT].sender = connection_timeout_sender;
    controllers[index + CQ_CONNECTION_TIMEOUT].receiver = connection_timeout_receiver;
    descriptions[index + CQ_CONNECTION_TIMEOUT] = "Get Connection Timeout";

    // X'0B'   Get User Total Current Connections
    controllers[index + CQ_USER_TOTAL_CONCURRENT_CONNECTIONS].sender = user_total_concurrent_connections_sender;
    controllers[index + CQ_USER_TOTAL_CONCURRENT_CONNECTIONS].receiver = user_total_concurrent_connections_receiver;
    descriptions[index + CQ_USER_TOTAL_CONCURRENT_CONNECTIONS] = "Get User Total Current Connections";
}

static void client_command_controller_load_modifications(CommandController controllers[], char *descriptions[]) {
    
    size_t index = CCSI_MODIFICATIONS;

    //  X'00'   Add User
    controllers[index + CM_ADD_USER].sender = add_user_sender;
    controllers[index + CM_ADD_USER].receiver = add_user_receiver;
    descriptions[index + CM_ADD_USER] = "Add User";

    // X'01'   Remove User
    controllers[index + CM_REMOVE_USER].sender = remove_user_sender;
    controllers[index + CM_REMOVE_USER].receiver = remove_user_receiver;
    descriptions[index + CM_REMOVE_USER] = "Remove User";

    // X'02'   Enable/Disable Password Spoofing
    controllers[index + CM_TOGGLE_PASSWORD_SPOOFING].sender = toggle_password_spoofing_sender;
    controllers[index + CM_TOGGLE_PASSWORD_SPOOFING].receiver = toggle_password_spoofing_receiver;
    descriptions[index + CM_TOGGLE_PASSWORD_SPOOFING] = "Enable/Disable Password Spoofing";

    // X'03'   Enable/Disable Connection Clean-up Routine
    controllers[index + CM_TOGGLE_CONNECTION_CLEAN_UN].sender = toggle_connection_clean_up_sender;
    controllers[index + CM_TOGGLE_CONNECTION_CLEAN_UN].receiver = toggle_connection_clean_up_receiver;
    descriptions[index + CM_TOGGLE_CONNECTION_CLEAN_UN] = "Enable/Disable Connection Clean-up Routine";
    
    // X'04'   Set I/O Buffer Sizes
    controllers[index + CM_SET_BUFFER_SIZE].sender = set_buffer_size_sender;
    controllers[index + CM_SET_BUFFER_SIZE].receiver = set_buffer_size_receiver;
    descriptions[index + CM_SET_BUFFER_SIZE] = "Set I/O Buffer Sizes";
    
    // X'05'   Set Selector Timeout
    controllers[index + CM_SET_SELECTOR_TIMEOUT].sender = set_selector_timeout_sender;
    controllers[index + CM_SET_SELECTOR_TIMEOUT].receiver = set_selector_timeout_receiver;
    descriptions[index + CM_SET_SELECTOR_TIMEOUT] = "Set Selector Timeout";
    
    // X'06'   Set Connection Timeout
    controllers[index + CM_SET_CONNECTION_TIMEOUT].sender = set_connection_timeout_sender;
    controllers[index + CM_SET_CONNECTION_TIMEOUT].receiver = set_connection_timeout_receiver;
    descriptions[index + CM_SET_CONNECTION_TIMEOUT] = "Set Connection Timeout";
}