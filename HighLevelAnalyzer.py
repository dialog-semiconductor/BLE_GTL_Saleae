# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
# Author :Niek Ilmer

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

MSG_ID_dict = {
'GATTM_ADD_SVC_REQ': 0x0B00,
'GATTM_ADD_SVC_RSP': 0x0B01,
'GATTM_SVC_GET_PERMISSION_REQ': 0x0B02,
'GATTM_SVC_GET_PERMISSION_RSP': 0x0B03,
'GATTM_SVC_SET_PERMISSION_REQ': 0x0B04,
'GATTM_SVC_SET_PERMISSION_RSP': 0x0B05,
'GATTM_ATT_GET_PERMISSION_REQ': 0x0B06,
'GATTM_ATT_GET_PERMISSION_RSP': 0x0B07,
'GATTM_ATT_SET_PERMISSION_REQ': 0x0B08,
'GATTM_ATT_SET_PERMISSION_RSP': 0x0B09,
'GATTM_ATT_GET_VALUE_REQ': 0x0B0A,
'GATTM_ATT_GET_VALUE_RSP': 0x0B0B,
'GATTM_ATT_SET_VALUE_REQ': 0x0B0C,
'GATTM_ATT_SET_VALUE_RSP': 0x0B0D,
'GATTM_DESTROY_DB_REQ': 0x0B0E,
'GATTM_DESTROY_DB_RSP': 0x0B0F,
'GATTM_SVC_GET_LIST_REQ': 0x0B10,
'GATTM_SVC_GET_LIST_RSP': 0x0B11,
'GATTM_ATT_GET_INFO_REQ': 0x0B12,
'GATTM_ATT_GET_INFO_RSP': 0x0B13,
'GATTC_CMP_EVT': 0x0C00,
'GATTC_EXC_MTU_CMD': 0x0C01,
'GATTC_MTU_CHANGED_IND': 0x0C02,
'GATTC_DISC_CMD': 0x0C03,
'GATTC_DISC_SVC_IND': 0x0C04,
'GATTC_DISC_SVC_INCL_IND': 0x0C05,
'GATTC_DISC_CHAR_IND': 0x0C06,
'GATTC_DISC_CHAR_DESC_IND': 0x0C07,
'GATTC_READ_CMD': 0x0C08,
'GATTC_READ_IND': 0x0C09,
'GATTC_WRITE_CMD': 0x0C0A,
'GATTC_EXECUTE_WRITE_CMD': 0x0C0B,
'GATTC_EVENT_IND': 0x0C0C,
'GATTC_EVENT_REQ_IND': 0x0C0D,
'GATTC_EVENT_CFM': 0x0C0E,
'GATTC_REG_TO_PEER_EVT_CMD': 0x0C0F,
'GATTC_SEND_EVT_CMD': 0x0C10,
'GATTC_SEND_SVC_CHANGED_CMD': 0x0C11,
'GATTC_SVC_CHANGED_CFG_IND': 0x0C12,
'GATTC_READ_REQ_IND': 0x0C13,
'GATTC_READ_CFM': 0x0C14,
'GATTC_WRITE_REQ_IND': 0x0C15,
'GATTC_WRITE_CFM': 0x0C16,
'GATTC_ATT_INFO_REQ_IND': 0x0C17,
'GATTC_ATT_INFO_CFM': 0x0C18,
'GATTC_SDP_SVC_DISC_CMD': 0x0C19,
'GATTC_SDP_SVC_IND': 0x0C1A,
'GATTC_TRANSACTION_TO_ERROR_IND': 0x0C1B,
'GATTC_CLIENT_RTX_IND': 0x0C1C,
'GATTC_SERVER_RTX_IND': 0x0C1D,
'GAPM_CMP_EVT': 0x0D00,
'GAPM_DEVICE_READY_IND': 0x0D01,
'GAPM_RESET_CMD': 0x0D02,
'GAPM_CANCEL_CMD': 0x0D03,
'GAPM_SET_DEV_CONFIG_CMD': 0x0D04,
'GAPM_SET_CHANNEL_MAP_CMD': 0x0D05,
'GAPM_GET_DEV_INFO_CMD': 0x0D06,
'GAPM_DEV_VERSION_IND': 0x0D07,
'GAPM_DEV_BDADDR_IND': 0x0D08,
'GAPM_DEV_ADV_TX_POWER_IND': 0x0D09,
'GAPM_DBG_MEM_INFO_IND': 0x0D0A,
'GAPM_WHITE_LIST_MGT_CMD': 0x0D0B,
'GAPM_WHITE_LIST_SIZE_IND': 0x0D0C,
'GAPM_START_ADVERTISE_CMD': 0x0D0D,
'GAPM_UPDATE_ADVERTISE_DATA_CMD': 0x0D0E,
'GAPM_START_SCAN_CMD': 0x0D0F,
'GAPM_ADV_REPORT_IND': 0x0D10,
'GAPM_START_CONNECTION_CMD': 0x0D11,
'GAPM_PEER_NAME_IND': 0x0D12,
'GAPM_CONNECTION_CFM': 0x0D13,
'GAPM_RESOLV_ADDR_CMD': 0x0D14,
'GAPM_ADDR_SOLVED_IND': 0x0D15,
'GAPM_GEN_RAND_ADDR_CMD': 0x0D16,
'GAPM_USE_ENC_BLOCK_CMD': 0x0D17,
'GAPM_USE_ENC_BLOCK_IND': 0x0D18,
'GAPM_GEN_RAND_NB_CMD': 0x0D19,
'GAPM_GEN_RAND_NB_IND': 0x0D1A,
'GAPM_PROFILE_TASK_ADD_CMD': 0x0D1B,
'GAPM_PROFILE_ADDED_IND': 0x0D1C,
'GAPM_UNKNOWN_TASK_IND': 0x0D1D,
'GAPM_SUGG_DFLT_DATA_LEN_IND': 0x0D1E,
'GAPM_MAX_DATA_LEN_IND': 0x0D1F,
'GAPM_RAL_MGT_CMD': 0x0D20,
'GAPM_RAL_SIZE_IND': 0x0D21,
'GAPM_RAL_ADDR_IND': 0x0D22,
'GAPM_LIM_DISC_TO_IND': 0x0D23,
'GAPM_SCAN_TO_IND': 0x0D24,
'GAPM_ADDR_RENEW_TO_IND': 0x0D25,
'GAPM_UNKNOWN_TASK_MSG': 0x0D26,
'GAPM_USE_P256_BLOCK_CMD': 0x0D27,
'GAPM_USE_P256_BLOCK_IND': 0x0D28,
'GAPC_CMP_EVT': 0x0E00,
'GAPC_CONNECTION_REQ_IND': 0x0E01,
'GAPC_CONNECTION_CFM': 0x0E02,
'GAPC_DISCONNECT_IND': 0x0E03,
'GAPC_DISCONNECT_CMD': 0x0E04,
'GAPC_GET_INFO_CMD': 0x0E05,
'GAPC_PEER_ATT_INFO_IND': 0x0E06,
'GAPC_PEER_VERSION_IND': 0x0E07,
'GAPC_PEER_FEATURES_IND': 0x0E08,
'GAPC_CON_RSSI_IND': 0x0E09,
'GAPC_GET_DEV_INFO_REQ_IND': 0x0E0A,
'GAPC_GET_DEV_INFO_CFM': 0x0E0B,
'GAPC_SET_DEV_INFO_REQ_IND': 0x0E0C,
'GAPC_SET_DEV_INFO_CFM': 0x0E0D,
'GAPC_PARAM_UPDATE_CMD': 0x0E0E,
'GAPC_PARAM_UPDATE_REQ_IND': 0x0E0F,
'GAPC_PARAM_UPDATE_CFM': 0x0E10,
'GAPC_PARAM_UPDATED_IND': 0x0E11,
'GAPC_BOND_CMD': 0x0E12,
'GAPC_BOND_REQ_IND': 0x0E13,
'GAPC_BOND_CFM': 0x0E14,
'GAPC_BOND_IND': 0x0E15,
'GAPC_ENCRYPT_CMD': 0x0E16,
'GAPC_ENCRYPT_REQ_IND': 0x0E17,
'GAPC_ENCRYPT_CFM': 0x0E18,
'GAPC_ENCRYPT_IND': 0x0E19,
'GAPC_SECURITY_CMD': 0x0E1A,
'GAPC_SECURITY_IND': 0x0E1B,
'GAPC_SIGN_COUNTER_IND': 0x0E1C,
'GAPC_CON_CHANNEL_MAP_IND': 0x0E1D,
'GAPC_LECB_CREATE_CMD': 0x0E1E,
'GAPC_LECB_DESTROY_CMD': 0x0E1F,
'GAPC_LECB_CONNECT_CMD': 0x0E20,
'GAPC_LECB_CONNECT_REQ_IND': 0x0E21,
'GAPC_LECB_CONNECT_IND': 0x0E22,
'GAPC_LECB_CONNECT_CFM': 0x0E23,
'GAPC_LECB_ADD_CMD': 0x0E24,
'GAPC_LECB_ADD_IND': 0x0E25,
'GAPC_LECB_DISCONNECT_CMD': 0x0E26,
'GAPC_LECB_DISCONNECT_IND': 0x0E27,
'GAPC_SET_LE_PING_TO_CMD': 0x0E28,
'GAPC_LE_PING_TO_VAL_IND': 0x0E29,
'GAPC_LE_PING_TO_IND': 0x0E2A,
'GAPC_SET_LE_PKT_SIZE_CMD': 0x0E2B,
'GAPC_LE_PKT_SIZE_IND': 0x0E2C,
'GAPC_SIGN_CMD': 0x0E2D,
'GAPC_SIGN_IND': 0x0E2E,
'GAPC_PARAM_UPDATE_TO_IND': 0x0E2F,
'GAPC_SMP_TIMEOUT_TIMER_IND': 0x0E30,
'GAPC_SMP_REP_ATTEMPTS_TIMER_IND': 0x0E31,
'GAPC_LECB_CONN_TO_IND': 0x0E32,
'GAPC_LECB_DISCONN_TO_IND': 0x0E33,
'GAPC_KEYPRESS_NOTIFICATION': 0x0E34,
'GAPC_KEYPRESS_NOTIFICATION_CMD': 0x0E35,
'GAPC_KEYPRESS_NOTIFICATION_IND': 0x0E36,
'SYS_APP_WRITE_CMD_REQ_IND': 0x0F01,
'APP_GEN_RAND_REQ': 0xA001,
'APP_GEN_RAND_RSP': 0xA002,
'APP_GET_FW_VERSION': 0xA003,
'APP_FW_VERSION_IND': 0xA004,
'APP_BOOT_FROM_EXTERNAL_HOST_CMD': 0xA005,
'APP_BOOT_FROM_EXTERNAL_HOST_IND': 0xA006
}

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    #my_string_setting = StringSetting()
    #my_number_setting = NumberSetting(min_value=0, max_value=100)
    #my_choices_setting = ChoicesSetting(choices=('A', 'B'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'gtl': {
            'format': 'Message ID: {{data.MSG_ID}}({{data.MSG_ID_decoded}}), Dest ID: {{data.DST_ID}}, Source ID: {{data.SRC_ID}}, Parameter length: {{data.PAR_LEN}}, Data: {{data.data}}'
        },
        'error': {
            'format': 'Error: {{data.error}}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        
        Settings can be accessed using the same name used above.
        '''
        self.receive_buffer_pointer = 0;
        self.receiveBuffer = [];
   
        print("Dialog Semiconductor GTL interface decoder by Niek Ilmer")

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        uartbuffer = int(frame.data['data'][0])
        if (( self.receive_buffer_pointer == 0 and uartbuffer == 5) or self.receive_buffer_pointer > 0 and (not 'error' in frame.data)):
            if self.receive_buffer_pointer == 0:
                self.startTime = frame.start_time #capture the start
                self.receiveBuffer = [uartbuffer]; 
            else:
                self.receiveBuffer.append(uartbuffer);
            if(self.receive_buffer_pointer >= 8):#Byte 7 and 8 tell how big the message is
                MSG_ID = self.receiveBuffer[2] << 8 | self.receiveBuffer[1]; #Extract the message ID from the message
                DST_ID = self.receiveBuffer[4] << 8 | self.receiveBuffer[3]; #Extract the destination ID from the message
                SRC_ID = self.receiveBuffer[6] << 8 | self.receiveBuffer[5]; #Extract the source ID from the message
                PAR_LEN = self.receiveBuffer[8] << 8 | self.receiveBuffer[7]; #Extract the parameter length from the message
                if ( self.receive_buffer_pointer >= PAR_LEN + 8): #Check to see if the entire message has been received
                    MSG_ID_decoded = 'unknown'
                    try:
                        MSG_ID_decoded = list(MSG_ID_dict.keys())[list(MSG_ID_dict.values()).index(MSG_ID)]
                    except ValueError: #Unknown ID
                        pass
                    tempMSG = AnalyzerFrame('gtl', self.startTime, frame.end_time, {'MSG_ID': hex(MSG_ID),'DST_ID': hex(DST_ID),'SRC_ID': hex(SRC_ID),'PAR_LEN': hex(PAR_LEN),'data': bytes(self.receiveBuffer[9:]), 'rawdata' : bytes(self.receiveBuffer).hex(" "), 'MSG_ID_decoded' : MSG_ID_decoded})
                    self.receive_buffer_pointer = -1
            if frame.start_time - self.startTime > (frame.end_time-frame.start_time) * 400:
                tempMSG = AnalyzerFrame('error', self.startTime, frame.end_time, {'error': 'Timeout'})
                self.receive_buffer_pointer = -1
            self.receive_buffer_pointer += 1;
            if (self.receive_buffer_pointer == 0):
                return tempMSG

